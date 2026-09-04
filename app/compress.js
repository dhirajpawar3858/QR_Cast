/**
 * compress.js - gzip / gunzip using the native CompressionStream API.
 * 
 * CompressionStream('gzip') / DecompressionStream('gzip') are supported in
 * modern Chromium (Edge/Chrome on Windows 11). We feature-detect and, if the
 * API is missing, fall back to "store" mode (no compression) so the transfer
 * still works - the HEADER's gzip flag records which path was used, so the
 * receiver always knows whether to inflate.
 */

/** True if the browser can gzip/gunzip natively. */
function hasCompressionStream() {
    return typeof CompressionStream !== 'undefined' &&
           typeof DecompressionStream !== 'undefined';
}

/** Read a ReadableStream of Uint8Array chunks into one Uint8Array. */
async function streamToBytes(stream) {
    const reader = stream.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.length;
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
}

/** Push bytes through a transform stream and collect the result. */
async function pipeThrough(bytes, transform) {
    const src = new Blob([bytes]).stream();
    return streamToBytes(src.pipeThrough(transform));
}

/** gzip-compress bytes. Returns Uint8Array. */
async function gzip(bytes) {
    if (!hasCompressionStream()) return bytes; // caller records gzip=false
    return pipeThrough(bytes, new CompressionStream('gzip'));
}

/** gunzip bytes previously produced by gzip(). Returns Uint8Array. */
async function gunzip(bytes) {
    if (!hasCompressionStream()) {
        throw new Error('This browser cannot decompress (no DecompressionStream).');
    }
    return pipeThrough(bytes, new DecompressionStream('gzip'));
}

window.Compress = {
    hasCompressionStream,
    gzip,
    gunzip,
};