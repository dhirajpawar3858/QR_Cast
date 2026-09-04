/**
 * packet.js - Binary frame format for animated-QR file transfer.
 * 
 * Every QR frame carries a raw byte array (QR "byte mode"). There are two
 * frame types that share a common 7-byte header:
 * 
 * Common header (7 bytes)
 * off 0 size 2 magic 0x51 0x52 ("QR")
 * off 2 size 1 version format version = 0x01
 * off 3 size 1 frameType 0x00 = HEADER, 0x01 = DATA
 * off 4 size 3 transferId random per transfer (guards against mixing
 * frames from two different transfers)
 * 
 * HEADER body (frameType 0x00) - the "manifest". Re-broadcast periodically
 * so a receiver that joins late still learns how to reassemble/decrypt.
 * size 2 totalChunks number of DATA frames
 * size 4 cipherLen total ciphertext length in bytes
 * size 16 salt PBKDF2 salt
 * size 12 iv AES-GCM IV
 * size 4 pbkdf2Iters PBKDF2 iteration count
 * size 1 flags bit0 = payload was gzip-compressed
 * size 32 cipherSha256 SHA-256 of the full ciphertext (final integrity)
 * size 1 nameLen filename length in bytes
 * size N filename UTF-8
 * size 4 headerCrc32 CRC32 over everything above (from magic)
 * 
 * DATA body (frameType 0x01)
 * size 2 chunkIndex 0-based index of this ciphertext slice
 * size 2 payloadLen number of ciphertext bytes in this frame
 * size P payload raw ciphertext slice
 * size 4 crc32 CRC32 over the payload (per-frame validity)
 * 
 * All multi-byte integers are big-endian. Pure functions only - no DOM, no
 * crypto - so this file is trivially testable on its own.
 */

const MAGIC0 = 0x51; // 'Q'
const MAGIC1 = 0x52; // 'R'
const FORMAT_VERSION = 0x01;

const FRAME_HEADER = 0x00;
const FRAME_DATA = 0x01;

const FLAG_GZIP = 0x01;

// ----------------------------------------------------------------------------
// CRC32 (IEEE 802.3, standard polynomial 0xEDB88320) - used for cheap
// per-frame corruption detection. Not cryptographic; SHA-256 in the HEADER
// provides the real end-to-end integrity check.
// ----------------------------------------------------------------------------
const CRC32_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) {
            c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        }
        table[n] = c >>> 0;
    }
    return table;
})();

/** Compute CRC32 over 'bytes' (optionally a sub-range). Returns a uint32. */
function crc32(bytes, start = 0, end = bytes.length) {
    let crc = 0xffffffff;
    for (let i = start; i < end; i++) {
        crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
}

// ----------------------------------------------------------------------------
// Small write/read helpers over a DataView-backed cursor.
// ----------------------------------------------------------------------------
class Writer {
    constructor(size) {
        this.buf = new Uint8Array(size);
        this.view = new DataView(this.buf.buffer);
        this.pos = 0;
    }
    u8(v) { this.view.setUint8(this.pos, v); this.pos += 1; return this; }
    u16(v) { this.view.setUint16(this.pos, v, false); this.pos += 2; return this; }
    u32(v) { this.view.setUint32(this.pos, v >>> 0, false); this.pos += 4; return this; }
    u24(v) {
        this.view.setUint8(this.pos, (v >>> 16) & 0xff);
        this.view.setUint8(this.pos + 1, (v >>> 8) & 0xff);
        this.view.setUint8(this.pos + 2, v & 0xff);
        this.pos += 3; return this;
    }
    bytes(arr) { this.buf.set(arr, this.pos); this.pos += arr.length; return this; }
}

class Reader {
    constructor(bytes) {
        this.buf = bytes;
        this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        this.pos = 0;
    }
    u8() { const v = this.view.getUint8(this.pos); this.pos += 1; return v; }
    u16() { const v = this.view.getUint16(this.pos, false); this.pos += 2; return v; }
    u32() { const v = this.view.getUint32(this.pos, false); this.pos += 4; return v >>> 0; }
    u24() {
        const v = (this.view.getUint8(this.pos) << 16) |
                  (this.view.getUint8(this.pos + 1) << 8) |
                  this.view.getUint8(this.pos + 2);
        this.pos += 3; return v >>> 0;
    }
    bytes(n) { const v = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return v; }
}

const HEADER_COMMON = 7; // magic(2) + version(1) + frameType(1) + transferId(3)

/**
 * Build a HEADER frame (Uint8Array) from a manifest object.
 * manifest: { transferId, totalChunks, cipherLen, salt(16), iv(12),
 *             pbkdf2Iters, gzip(bool), cipherSha256(32), filename(string) }
 */
function encodeHeader(manifest) {
    const nameBytes = new TextEncoder().encode(manifest.filename);
    if (nameBytes.length > 255) {
        throw new Error('Filename too long (max 255 bytes UTF-8).');
    }
    // body = totalChunks(2)+cipherLen(4)+salt(16)+iv(12)+iters(4)+flags(1)
    //        +sha(32)+nameLen(1)+name(N)
    const bodyLen = 2 + 4 + 16 + 12 + 4 + 1 + 32 + 1 + nameBytes.length;
    const total = HEADER_COMMON + bodyLen + 4; // + headerCrc32
    const w = new Writer(total);

    w.u8(MAGIC0).u8(MAGIC1).u8(FORMAT_VERSION).u8(FRAME_HEADER).u24(manifest.transferId);
    w.u16(manifest.totalChunks);
    w.u32(manifest.cipherLen);
    w.bytes(manifest.salt);
    w.bytes(manifest.iv);
    w.u32(manifest.pbkdf2Iters);
    w.u8(manifest.gzip ? FLAG_GZIP : 0);
    w.bytes(manifest.cipherSha256);
    w.u8(nameBytes.length);
    w.bytes(nameBytes);

    const crc = crc32(w.buf, 0, w.pos); // CRC over everything written so far
    w.u32(crc);
    return w.buf;
}

/**
 * Build a DATA frame (Uint8Array).
 * transferId: uint24, chunkIndex: uint16, payload: Uint8Array slice.
 */
function encodeData(transferId, chunkIndex, payload) {
    const total = HEADER_COMMON + 2 + 2 + payload.length + 4;
    const w = new Writer(total);
    w.u8(MAGIC0).u8(MAGIC1).u8(FORMAT_VERSION).u8(FRAME_DATA).u24(transferId);
    w.u16(chunkIndex);
    w.u16(payload.length);
    w.bytes(payload);
    w.u32(crc32(payload));
    return w.buf;
}

/**
 * Decode any frame. Returns a tagged object or throws on malformed/corrupt
 * input (bad magic, unknown version, or CRC mismatch). Callers should treat a
 * throw as "drop this frame and keep scanning".
 * 
 * HEADER -> { type: 'header', transferId, totalChunks, cipherLen, salt, iv,
 *             pbkdf2Iters, gzip, cipherSha256, filename }
 * DATA   -> { type: 'data', transferId, chunkIndex, payload }
 */
function decodeFrame(bytes) {
    if (!bytes || bytes.length < HEADER_COMMON) {
        throw new Error('Frame too short.');
    }
    const r = new Reader(bytes);
    if (r.u8() !== MAGIC0 || r.u8() !== MAGIC1) throw new Error('Bad magic.');
    const version = r.u8();
    if (version !== FORMAT_VERSION) throw new Error('Unsupported format version ' + version);
    const frameType = r.u8();
    const transferId = r.u24();

    if (frameType === FRAME_HEADER) {
        const totalChunks = r.u16();
        const cipherLen = r.u32();
        const salt = r.bytes(16);
        const iv = r.bytes(12);
        const pbkdf2Iters = r.u32();
        const flags = r.u8();
        const cipherSha256 = r.bytes(32);
        const nameLen = r.u8();
        const filename = new TextDecoder().decode(r.bytes(nameLen));
        const crcGiven = r.u32();
        const crcCalc = crc32(bytes, 0, bytes.length - 4);
        if (crcGiven !== crcCalc) throw new Error('HEADER CRC mismatch.');
        return {
            type: 'header',
            transferId, totalChunks, cipherLen,
            // copy so the returned data does not alias the transient scan buffer
            salt: salt.slice(), iv: iv.slice(),
            pbkdf2Iters, gzip: (flags & FLAG_GZIP) !== 0,
            cipherSha256: cipherSha256.slice(), filename,
        };
    }

    if (frameType === FRAME_DATA) {
        const chunkIndex = r.u16();
        const payloadLen = r.u16();
        const payload = r.bytes(payloadLen);
        const crcGiven = r.u32();
        if (crc32(payload) !== crcGiven) throw new Error('DATA CRC mismatch.');
        return { type: 'data', transferId, chunkIndex, payload: payload.slice() };
    }

    throw new Error('Unknown frame type ' + frameType);
}

// Overhead of a DATA frame excluding the payload itself:
// common(7) + chunkIndex(2) + payloadLen(2) + crc32(4) = 15
const DATA_FRAME_OVERHEAD = HEADER_COMMON + 2 + 2 + 4;

// Expose as a global namespace (no modules / no bundler - plain <script>).
window.Packet = {
    crc32,
    encodeHeader,
    encodeData,
    decodeFrame,
    DATA_FRAME_OVERHEAD,
    FORMAT_VERSION,
};