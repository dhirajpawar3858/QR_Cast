/*
 * sender.js — Read a file, compress, encrypt, split into binary QR frames, and
 * play them as an animated QR sequence.
 *
 * Pipeline on "Start":
 *   file bytes -> gzip -> AES-GCM encrypt -> slice into payloads
 *              -> wrap each payload in a DATA frame (packet.js)
 *              -> build one HEADER frame (manifest)
 *   Broadcast loop: HEADER, then DATA 0..N, re-inserting HEADER every ~15
 *   frames so a late-joining receiver can still learn the manifest. Loops
 *   until stopped so the receiver can fill in any frames it missed.
 *
 * Everything runs locally; no network calls.
 */
(function () {
  'use strict';

  // Max QR version-40 byte-mode capacity per ECC level (raw bytes the symbol
  // can hold). Used to cap the payload slider so QRCode never overflows.
  const V40_BYTE_CAPACITY = { L: 2953, M: 2331, Q: 1663, H: 1273 };

  const $ = (id) => document.getElementById(id);

  const el = {
    dropzone: $('dropzone'),
    fileInput: $('fileInput'),
    fileInfo: $('fileInfo'),
    passphrase: $('passphrase'),
    togglePass: $('togglePass'),
    payload: $('payload'),
    payloadVal: $('payloadVal'),
    ecc: $('ecc'),
    fps: $('fps'),
    fpsVal: $('fpsVal'),
    scale: $('scale'),
    scaleVal: $('scaleVal'),
    estimate: $('estimate'),
    startBtn: $('startBtn'),
    stopBtn: $('stopBtn'),
    loopChk: $('loopChk'),
    genStatus: $('genStatus'),
    qrCanvas: $('qrCanvas'),
    frameLabel: $('frameLabel'),
    frameBar: $('frameBar'),
    // Chunk selection grid
    chunkPanel: $('chunkPanel'),
    chunkGrid: $('chunkGrid'),
    chunkGridWrap: $('chunkGridWrap'),
    marquee: $('marquee'),
    selectModeChk: $('selectModeChk'),
    clearSelBtn: $('clearSelBtn'),
    chunkStat: $('chunkStat'),
  };

  let fileBytes = null;     // Uint8Array of the selected file
  let fileName = '';
  let frames = [];          // Array<Uint8Array> — the full broadcast sequence
  let playIndex = 0;
  let playTimer = null;
  // Per-chunk DATA frames + the HEADER frame are kept around after build so the
  // broadcast sequence can be rebuilt on the fly when the user marks chunks as
  // already received (acked). Only non-acked chunks get animated.
  let dataFrames = [];      // Array<Uint8Array>, index === chunkIndex
  let headerFrame = null;   // the manifest frame (re-inserted periodically)
  let ackedChunks = new Set(); // chunk indices the receiver already has
  // Rendering is locked to ONE QR version + pixel width for the whole
  // sequence so frames don't visibly grow/shrink ("blink") between the small
  // HEADER frame and the larger DATA frames. Computed once in buildFrames().
  let renderVersion = null; // fixed QR version (1..40)
  let renderWidth = 0;      // fixed canvas pixel width

  // ---- Helpers -----------------------------------------------------------

  function setStatus(node, msg, kind) {
    node.textContent = msg;
    node.className = 'status' + (kind ? ' ' + kind : '');
    node.classList.remove('hidden');
  }

  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(2) + ' MB';
  }

  function fmtTime(sec) {
    if (sec < 60) return sec.toFixed(1) + ' s';
    const m = Math.floor(sec / 60);
    const s = Math.round(sec % 60);
    return m + ' m ' + s + ' s';
  }

  /** Effective usable payload per frame given the ECC cap and the slider. */
  function usablePayload() {
    const cap = V40_BYTE_CAPACITY[el.ecc.value] - window.Packet.DATA_FRAME_OVERHEAD;
    return Math.min(parseInt(el.payload.value, 10), cap);
  }

  // ---- Estimate ----------------------------------------------------------

  function updateEstimate() {
    el.payloadVal.textContent = el.payload.value + ' B';
    el.fpsVal.textContent = el.fps.value;
    el.scaleVal.textContent = el.scale.value;

    if (!fileBytes) {
      el.estimate.textContent = 'Choose a file to see chunk count and transfer time.';
      return;
    }
    const usable = usablePayload();
    const fps = parseInt(el.fps.value, 10);
    // NOTE: this is a pre-compression/pre-encryption estimate. Encryption adds
    // a 16-byte tag; gzip usually shrinks source/text a lot. We estimate on the
    // raw size as an upper bound for incompressible data.
    const approxCipher = fileBytes.length + 16;
    const dataFrames = Math.ceil(approxCipher / usable);
    const totalFrames = dataFrames + Math.ceil(dataFrames / 15) + 1; // + HEADERs
    const loopSec = totalFrames / fps;
    const capNote = parseInt(el.payload.value, 10) > usable
      ? ` (capped to ${usable} B by ECC ${el.ecc.value})` : '';
    el.estimate.innerHTML =
      `≈ <b>${dataFrames}</b> data frames · usable <b>${usable}</b> B/frame${capNote}<br>` +
      `≈ <b>${totalFrames}</b> total frames/loop · one loop ≈ <b>${fmtTime(loopSec)}</b> at ${fps} fps<br>` +
      `<span class="muted">Text/code compresses well, so the real count is usually lower.</span>`;
    el.estimate.classList.remove('muted');
  }

  // ---- File selection ----------------------------------------------------

  async function loadFile(file) {
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      setStatus(el.fileInfo, `File is ${fmtBytes(file.size)} — max supported is 2 MB.`, 'err');
      fileBytes = null;
      el.startBtn.disabled = true;
      return;
    }
    fileBytes = new Uint8Array(await file.arrayBuffer());
    fileName = file.name;
    setStatus(el.fileInfo, `Selected: ${file.name} — ${fmtBytes(file.size)}`, 'ok');
    el.startBtn.disabled = false;
    updateEstimate();
  }

  // ---- Build frames ------------------------------------------------------

  async function buildFrames() {
    const pass = el.passphrase.value;
    if (!pass) throw new Error('Enter a passphrase first.');

    // 1. Compress
    let payload = fileBytes;
    let gzipUsed = false;
    if (window.Compress.hasCompressionStream()) {
      const gz = await window.Compress.gzip(fileBytes);
      // Only keep compression if it actually helped.
      if (gz.length < fileBytes.length) { payload = gz; gzipUsed = true; }
    }

    // 2. Encrypt (PBKDF2 -> AES-GCM)
    const salt = window.Crypto2.randomBytes(window.Crypto2.SALT_BYTES);
    const iv = window.Crypto2.randomBytes(window.Crypto2.IV_BYTES);
    const iters = window.Crypto2.DEFAULT_PBKDF2_ITERS;
    const key = await window.Crypto2.deriveKey(pass, salt, iters);
    const cipher = await window.Crypto2.encrypt(key, iv, payload);
    const cipherSha = await window.Crypto2.sha256(cipher);

    // 3. Slice into DATA frames
    const usable = usablePayload();
    const transferId = (window.Crypto2.randomBytes(3).reduce((a, b) => (a << 8) | b, 0)) >>> 0;
    dataFrames = [];
    let idx = 0;
    for (let off = 0; off < cipher.length; off += usable) {
      const slice = cipher.subarray(off, Math.min(off + usable, cipher.length));
      dataFrames.push(window.Packet.encodeData(transferId, idx, slice));
      idx += 1;
    }
    const totalChunks = dataFrames.length;

    // 4. HEADER frame (manifest)
    headerFrame = window.Packet.encodeHeader({
      transferId,
      totalChunks,
      cipherLen: cipher.length,
      salt, iv,
      pbkdf2Iters: iters,
      gzip: gzipUsed,
      cipherSha256: cipherSha,
      filename: fileName,
    });

    // 5. Fresh transfer: nothing acked yet. Build the initial sequence
    //    (all chunks) and the clickable grid.
    ackedChunks = new Set();
    buildSenderGrid(totalChunks);
    rebuildSequence();

    // 6. Lock the QR version so EVERY frame renders at the same grid/pixel
    //    size (no blinking). The largest frame needs the biggest version;
    //    ask node-qrcode which version fits it, then reuse that for all frames.
    const largest = frames.reduce((a, b) => (b.length > a.length ? b : a), frames[0]);
    const probe = QRCode.create([{ data: largest, mode: 'byte' }],
      { errorCorrectionLevel: el.ecc.value });
    renderVersion = probe.version;
    const modules = probe.modules.size;              // grid cells per side
    const margin = 2;
    renderWidth = (modules + margin * 2) * parseInt(el.scale.value, 10);

    return { totalChunks, cipherLen: cipher.length, gzipUsed };
  }

  // ---- Broadcast sequence (only the still-missing chunks) ----------------

  /**
   * Rebuild `frames` from `dataFrames`, skipping any chunk the user has marked
   * as already received. HEADER is placed first and re-inserted every 15 data
   * frames so a late-joining receiver still learns the manifest.
   */
  function rebuildSequence() {
    if (!headerFrame) return;
    const missing = [];
    for (let i = 0; i < dataFrames.length; i++) {
      if (!ackedChunks.has(i)) missing.push(dataFrames[i]);
    }
    const seq = [headerFrame];
    for (let i = 0; i < missing.length; i++) {
      seq.push(missing[i]);
      if ((i + 1) % 15 === 0 && i + 1 < missing.length) seq.push(headerFrame);
    }
    frames = seq;
    if (playIndex >= frames.length) playIndex = 0;
    updateChunkStat();
  }

  function updateChunkStat() {
    if (!el.chunkStat || dataFrames.length === 0) return;
    const total = dataFrames.length;
    const acked = ackedChunks.size;
    const missing = total - acked;
    el.chunkStat.textContent =
      `${missing} of ${total} chunks still broadcasting · ${acked} marked received`;
    el.chunkStat.classList.remove('muted');
  }

  // ---- Chunk grid + rectangle (marquee) selection ------------------------

  function buildSenderGrid(n) {
    el.chunkGrid.innerHTML = '';
    for (let i = 0; i < n; i++) {
      const d = document.createElement('div');
      d.className = 'cell';
      d.dataset.idx = i;
      el.chunkGrid.appendChild(d);
    }
    el.chunkPanel.classList.remove('hidden');
    refreshGridClasses();
  }

  function refreshGridClasses() {
    const cells = el.chunkGrid.children;
    for (let i = 0; i < cells.length; i++) {
      cells[i].classList.toggle('got', ackedChunks.has(i));
    }
  }

  // Pointer-based selection: works for mouse, touch and pen via Pointer Events.
  let dragging = false;
  let startX = 0, startY = 0;        // marquee origin, relative to the wrapper
  let downClientX = 0, downClientY = 0;
  let addMode = true;                // true = mark received, false = un-mark
  const CLICK_SLOP = 10;             // px of movement before it counts as a drag

  function localPoint(e) {
    const r = el.chunkGridWrap.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  }

  // Find the .cell under a screen point. Needed because setPointerCapture makes
  // pointerup's e.target the grid container, not the cell under the pointer.
  function cellAtClient(clientX, clientY) {
    const node = document.elementFromPoint(clientX, clientY);
    const cell = node && node.closest ? node.closest('.cell') : null;
    return (cell && cell.parentElement === el.chunkGrid) ? cell : null;
  }

  function onPointerDown(e) {
    if (e.button !== undefined && e.button > 0) return; // left/primary/touch only
    e.preventDefault();
    try { el.chunkGrid.setPointerCapture(e.pointerId); } catch (_) {}
    dragging = true;
    const p = localPoint(e);
    startX = p.x; startY = p.y;
    downClientX = e.clientX; downClientY = e.clientY;
    // add vs. remove: Alt or an unchecked box forces "remove"; otherwise toggle
    // based on the cell we started on (drag over marked cells un-marks them).
    const startCell = cellAtClient(e.clientX, e.clientY);
    const startAcked = startCell ? ackedChunks.has(+startCell.dataset.idx) : false;
    if (e.altKey || !el.selectModeChk.checked) addMode = false;
    else addMode = !startAcked;
    el.chunkGrid.classList.add('selecting');
  }

  function onPointerMove(e) {
    if (!dragging) return;
    const p = localPoint(e);
    const x = Math.min(startX, p.x), y = Math.min(startY, p.y);
    const w = Math.abs(p.x - startX), h = Math.abs(p.y - startY);
    el.marquee.style.left = x + 'px';
    el.marquee.style.top = y + 'px';
    el.marquee.style.width = w + 'px';
    el.marquee.style.height = h + 'px';
    el.marquee.classList.remove('hidden');
  }

  function onPointerUp(e) {
    if (!dragging) return;
    dragging = false;
    el.chunkGrid.classList.remove('selecting');
    el.marquee.classList.add('hidden');

    const moved = Math.hypot(e.clientX - downClientX, e.clientY - downClientY);

    if (moved < CLICK_SLOP) {
      // Single click / tap: toggle the one cell under the pointer. Use
      // coordinates (not e.target) because pointer capture makes e.target the grid.
      const cell = cellAtClient(e.clientX, e.clientY);
      if (cell) {
        const idx = +cell.dataset.idx;
        if (ackedChunks.has(idx)) ackedChunks.delete(idx);
        else ackedChunks.add(idx);
      }
    } else {
      // Drag rectangle: hit-test every cell against the selection box.
      const p = localPoint(e);
      const rect = {
        left: Math.min(startX, p.x), top: Math.min(startY, p.y),
        right: Math.max(startX, p.x), bottom: Math.max(startY, p.y),
      };
      const wrapRect = el.chunkGridWrap.getBoundingClientRect();
      const cells = el.chunkGrid.children;
      for (let i = 0; i < cells.length; i++) {
        const c = cells[i].getBoundingClientRect();
        const cl = c.left - wrapRect.left, ct = c.top - wrapRect.top;
        const cr = c.right - wrapRect.left, cb = c.bottom - wrapRect.top;
        const hit = cl < rect.right && cr > rect.left &&
                    ct < rect.bottom && cb > rect.top;
        if (hit) {
          if (addMode) ackedChunks.add(i);
          else ackedChunks.delete(i);
        }
      }
    }

    refreshGridClasses();
    rebuildSequence();   // re-animate only the still-missing chunks
  }

  function clearSelection() {
    ackedChunks = new Set();
    refreshGridClasses();
    rebuildSequence();
  }

  // ---- Render one frame to the canvas -----------------------------------

  function renderFrame(bytes) {
    // node-qrcode byte-mode segment: pass raw bytes with mode 'byte'.
    // `version` is pinned so smaller frames pad up to the same size as the
    // largest — the symbol stays a constant size across the whole animation.
    const segs = [{ data: bytes, mode: 'byte' }];
    QRCode.toCanvas(el.qrCanvas, segs, {
      errorCorrectionLevel: el.ecc.value,
      version: renderVersion || undefined,
      width: renderWidth || undefined,
      margin: 2,
      color: { dark: '#1c1533', light: '#ffffff' },
    }, (err) => {
      if (err) setStatus(el.genStatus, 'QR render error: ' + err.message, 'err');
    });
  }

  // ---- Playback loop -----------------------------------------------------

  function tick() {
    if (frames.length === 0) return;
    const frame = frames[playIndex];
    renderFrame(frame);
    el.frameLabel.textContent =
      `frame ${playIndex + 1} / ${frames.length}`;
    el.frameBar.style.width = ((playIndex + 1) / frames.length * 100) + '%';

    playIndex += 1;
    if (playIndex >= frames.length) {
      if (el.loopChk.checked) {
        playIndex = 0; // replay
      } else {
        stop();
        setStatus(el.genStatus, 'Broadcast complete (looping is off).', 'ok');
        return;
      }
    }
  }

  function startTimer() {
    stopTimer();
    const fps = parseInt(el.fps.value, 10);
    playTimer = setInterval(tick, Math.max(1000 / fps, 30));
  }
  function stopTimer() {
    if (playTimer) { clearInterval(playTimer); playTimer = null; }
  }

  async function start() {
    try {
      el.startBtn.disabled = true;
      setStatus(el.genStatus, 'Compressing & encrypting…', 'warn');
      const built = await buildFrames();
      playIndex = 0;
      setStatus(el.genStatus,
        `Broadcasting ${built.totalChunks} chunks (${fmtBytes(built.cipherLen)} ciphertext` +
        `${built.gzipUsed ? ', gzip' : ', stored'}). Point the receiver's camera at the QR.`,
        'ok');
      el.stopBtn.disabled = false;
      startTimer();
    } catch (e) {
      setStatus(el.genStatus, e.message, 'err');
      el.startBtn.disabled = false;
    }
  }

  function stop() {
    stopTimer();
    el.startBtn.disabled = !fileBytes;
    el.stopBtn.disabled = true;
  }

  // ---- Wire up events ----------------------------------------------------

  el.dropzone.addEventListener('click', () => el.fileInput.click());
  el.fileInput.addEventListener('change', (e) => loadFile(e.target.files[0]));

  ['dragenter', 'dragover'].forEach((ev) =>
    el.dropzone.addEventListener(ev, (e) => {
      e.preventDefault(); el.dropzone.classList.add('drag');
    }));
  ['dragleave', 'drop'].forEach((ev) =>
    el.dropzone.addEventListener(ev, (e) => {
      e.preventDefault(); el.dropzone.classList.remove('drag');
    }));
  el.dropzone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]);
  });

  el.togglePass.addEventListener('click', () => {
    const isPw = el.passphrase.type === 'password';
    el.passphrase.type = isPw ? 'text' : 'password';
    el.togglePass.textContent = isPw ? 'Hide' : 'Show';
  });

  [el.payload, el.ecc, el.fps, el.scale].forEach((c) =>
    c.addEventListener('input', () => {
      updateEstimate();
      if (playTimer) startTimer(); // apply new FPS live
    }));

  el.startBtn.addEventListener('click', start);
  el.stopBtn.addEventListener('click', () => {
    stop();
    setStatus(el.genStatus, 'Stopped.', 'warn');
  });

  // Chunk-grid selection: pointer events cover mouse, touch and pen.
  el.chunkGrid.addEventListener('pointerdown', onPointerDown);
  el.chunkGrid.addEventListener('pointermove', onPointerMove);
  el.chunkGrid.addEventListener('pointerup', onPointerUp);
  el.chunkGrid.addEventListener('pointercancel', () => {
    dragging = false;
    el.chunkGrid.classList.remove('selecting');
    el.marquee.classList.add('hidden');
  });
  el.clearSelBtn.addEventListener('click', clearSelection);

  // Initial UI state
  updateEstimate();
})();
