/*
 * receiver.js - Open the camera, scan animated QR frames with jsQR, collect
 * DATA chunks by index (deduping and skipping corrupt frames), learn the
 * manifest from HEADER frames, and once every chunk is present:
 *   reassemble ciphertext -> verify SHA-256 -> AES-GCM decrypt -> gunzip
 *   -> download with the original filename.
 * 
 * jsQR gives us result.binaryData (raw byte array), which is exactly the QR
 * byte-mode payload the sender wrote. Everything runs locally.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const el = {
    startCam: $('startCam'),
    stopCam: $('stopCam'),
    cameraSelect: $('cameraSelect'),
    video: $('video'),
    scanCanvas: $('scanCanvas'),
    camStatus: $('camStatus'),
    manifestInfo: $('manifestInfo'),
    recvBar: $('recvBar'),
    recvStat: $('recvStat'),
    chunkGrid: $('chunkGrid'),
    passphrase: $('passphrase'),
    togglePass: $('togglePass'),
    saveBtn: $('saveBtn'),
    saveStatus: $('saveStatus'),
  };

  let stream = null;
  let scanning = false;
  let rafId = null;
  const ctx = el.scanCanvas.getContext('2d', { willReadFrequently: true });

  // Transfer state
  let manifest = null;                    // decoded HEADER
  let chunks = null;                      // Array<Uint8Array | undefined>, length = totalChunks
  let receivedCount = 0;
  let activeTransferId = null;

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

  // ---- Manifest / grid ---------------------------------------------------

  function initTransfer(hdr) {
    manifest = hdr;
    activeTransferId = hdr.transferId;
    chunks = new Array(hdr.totalChunks);
    receivedCount = 0;
    el.manifestInfo.innerHTML =
      `File: <b>${hdr.filename}</b> • ${hdr.totalChunks} chunks • ` +
      `${fmtBytes(hdr.cipherLen)} ciphertext${hdr.gzip ? ' • gzip' : ''}`;
    el.manifestInfo.classList.remove('muted');
    buildGrid(hdr.totalChunks);
    updateProgress();
  }

  function buildGrid(n) {
    el.chunkGrid.innerHTML = '';
    // Cap DOM cells for very large transfers to keep the grid light.
    const cells = Math.min(n, 2000);
    for (let i = 0; i < cells; i++) {
      const d = document.createElement('div');
      d.className = 'cell';
      d.dataset.idx = 1;
      el.chunkGrid.appendChild(d);
    }
  }

  function markCell(idx) {
    // Grid may be down-sampled for huge transfers; map index -> cell.
    const cells = el.chunkGrid.children.length;
    if (cells === 0) return;
    const total = manifest ? manifest.totalChunks : cells;
    const cellIdx = Math.floor(idx / (total / cells));
    const cell = el.chunkGrid.children[cellIdx];
    if (cell) cell.classList.add('got');
  }

  function updateProgress() {
    if (!manifest) return;
    const pct = receivedCount / manifest.totalChunks * 100;
    el.recvBar.style.width = pct + '%';
    const missing = manifest.totalChunks - receivedCount;
    el.recvStat.textContent =
      `${receivedCount} / ${manifest.totalChunks} chunks • ${missing} missing`;
    el.recvStat.classList.remove('muted');
    if (missing === 0) {
      setStatus(el.saveStatus, 'All chunks received! Enter the passphrase and save.', 'ok');
      el.saveBtn.disabled = false;
    }
  }

  // ---- Frame handling ----------------------------------------------------

  function handleFrame(bytes) {
    let frame;
    try {
      frame = window.Packet.decodeFrame(bytes);
    } catch (e) {
      return; // corrupt / unrelated QR - ignore and keep scanning
    }

    if (frame.type === 'header') {
      // If this is a new transfer, (re)initialise. Otherwise ignore repeats.
      if (!manifest || frame.transferId !== activeTransferId) {
        initTransfer(frame);
      }
      return;
    }

    // DATA frame
    if (frame.type === 'data') {
      // Ignore frames from a different transfer than the one we're collecting.
      if (activeTransferId !== null && frame.transferId !== activeTransferId) return;
      // If we have no manifest yet, we can't size the array - buffer loosely.
      if (!chunks) return; // wait for a HEADER first
      if (frame.chunkIndex >= chunks.length) return; // out of range
      if (chunks[frame.chunkIndex]) return; // duplicate - already have it

      chunks[frame.chunkIndex] = frame.payload;
      receivedCount += 1;
      markCell(frame.chunkIndex);
      updateProgress();
    }
  }

  // ---- Camera scan loop --------------------------------------------------

  function scanLoop() {
    if (!scanning) return;
    if (el.video.readyState === el.video.HAVE_ENOUGH_DATA) {
      const w = el.video.videoWidth;
      const h = el.video.videoHeight;
      if (w && h) {
        el.scanCanvas.width = w;
        el.scanCanvas.height = h;
        ctx.drawImage(el.video, 0, 0, w, h);
        const img = ctx.getImageData(0, 0, w, h);
        const result = jsQR(img.data, w, h, { inversionAttempts: 'dontInvert' });
        if (result && result.binaryData && result.binaryData.length) {
          handleFrame(Uint8Array.from(result.binaryData));
        }
      }
    }
    rafId = requestAnimationFrame(scanLoop);
  }

  // ---- Camera control ----------------------------------------------------

  async function listCameras() {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      const cams = devices.filter((d) => d.kind === 'videoinput');
      el.cameraSelect.innerHTML = '';
      cams.forEach((c, i) => {
        const opt = document.createElement('option');
        opt.value = c.deviceId;
        opt.textContent = c.label || `Camera ${i + 1}`;
        el.cameraSelect.appendChild(opt);
      });
    } catch (_) { /* labels need permission; ignore */ }
  }

  async function startCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setStatus(el.camStatus, 'This browser has no camera API (getUserMedia).', 'err');
      return;
    }
    try {
      const deviceId = el.cameraSelect.value;
      const constraints = {
        video: deviceId
          ? { deviceId: { exact: deviceId } }
          : { facingMode: 'environment' },
        audio: false,
      };
      stream = await navigator.mediaDevices.getUserMedia(constraints);
      el.video.srcObject = stream;
      await el.video.play();
      scanning = true;
      el.startCam.disabled = true;
      el.stopCam.disabled = false;
      setStatus(el.camStatus, 'Scanning.. point at the sender\'s animated QR.', 'ok');
      el.startCam.disabled = true;
      el.stopCam.disabled = false;
      setStatus(el.camStatus, 'Scanning.. point at the sender\'s animated QR.', 'ok');
      await listCameras(); // now labels are available
      scanLoop();
    } catch (e) {
      setStatus(el.camStatus, 'Could not open camera: ' + e.message, 'err');
    }
  }

  function stopCamera() {
    scanning = false;
    if (rafId) cancelAnimationFrame(rafId);
    if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
    el.video.srcObject = null;
    el.startCam.disabled = false;
    el.stopCam.disabled = true;
    setStatus(el.camStatus, 'Camera stopped.', 'warn');
  }

  // ---- Reassemble / decrypt / save ---------------------------------------

  async function reconstructAndSave() {
    try {
      if (!manifest || receivedCount !== manifest.totalChunks) {
        throw new Error('Transfer is not complete yet.');
      }

      const pass = el.passphrase.value;
      if (!pass) throw new Error('Enter the passphrase.');

      setStatus(el.saveStatus, 'Reassembling...', 'warn');

      // 1. Concatenate ciphertext in index order.
      const cipher = new Uint8Array(manifest.cipherLen);
      let off = 0;
      for (let i = 0; i < chunks.length; i++) {
        const c = chunks[i];
        if (!c) throw new Error('Missing chunk ' + i + ' - keep scanning.');
        cipher.set(c, off);
        off += c.length;
      }
      if (off !== manifest.cipherLen) {
        throw new Error(`Reassembled size ${off} != expected ${manifest.cipherLen}.`);
      }

      // 2. Verify end-to-end integrity before spending effort on decryption.
      const sha = await window.Crypto2.sha256(cipher);
      if (!window.Crypto2.bytesEqual(sha, manifest.cipherSha256)) {
        throw new Error('Integrity check failed (SHA-256 mismatch). Data is corrupt.');
      }

      // 3. Decrypt (PBKDF2 -> AES-GCM). Wrong passphrase throws here.
      setStatus(el.saveStatus, 'Decrypting...', 'warn');
      const key = await window.Crypto2.deriveKey(pass, manifest.salt, manifest.pbkdf2Iters);
      let plain = await window.Crypto2.decrypt(key, manifest.iv, cipher);

      // 4. Decompress if the sender gzipped.
      if (manifest.gzip) {
        setStatus(el.saveStatus, 'Decompressing...', 'warn');
        plain = await window.Compress.gunzip(plain);
      }

      // 5. Trigger a download with the original filename.
      const blob = new Blob([plain], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = manifest.filename || 'received.bin';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);

      setStatus(
        el.saveStatus,
        `Saved "${manifest.filename}" (${fmtBytes(plain.length)}) ✓`, 'ok'
      );
    } catch (e) {
      setStatus(el.saveStatus, e.message, 'err');
    }
  }

  // ---- Events ------------------------------------------------------------

  el.startCam.addEventListener('click', startCamera);
  el.stopCam.addEventListener('click', stopCamera);
  el.cameraSelect.addEventListener('change', () => {
    if (scanning) { stopCamera(); startCamera(); }
  });
  el.saveBtn.addEventListener('click', reconstructAndSave);
  el.togglePass.addEventListener('click', () => {
    const isPw = el.passphrase.type === 'password';
    el.passphrase.type = isPw ? 'text' : 'password';
    el.togglePass.textContent = isPw ? 'Hide' : 'Show';
  });

  // Warn early if the browser can't decompress (needed if sender used gzip).
  if (!window.Compress.hasCompressionStream()) {
    setStatus(el.saveStatus,
      'Note: this browser lacks DecompressionStream. gzip transfers cannot be restored here.',
      'warn'
    );
  }
})();