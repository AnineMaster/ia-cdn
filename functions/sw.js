const MAX_CHUNK = 2 * 1024 * 1024;
const streams = new Map();

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('svid-streams-db', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('streams');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function dbSet(id, val) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('streams', 'readwrite');
    tx.objectStore('streams').put(val, id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
async function dbGet(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('streams', 'readonly');
    const req = tx.objectStore('streams').get(id);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function wordKey(k0, k1, k2, k3, salt, idx) {
  let x = (idx ^ salt) >>> 0;
  let y = (k0 ^ Math.imul(idx, 0x9e3779b9)) >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x85ebca6b) >>> 0;
  y = Math.imul(y ^ (y >>> 13), 0xc2b2ae35) >>> 0;
  let z = (x ^ y ^ k1) >>> 0;
  z = (z + k2) | 0;
  z = (z ^ (z >>> 15)) >>> 0;
  z = Math.imul(z, 0x27d4eb2f) >>> 0;
  return (z ^ k3 ^ (z >>> 16)) >>> 0;
}

function deriveKeys(keyStr, salt) {
  const bytes = new TextEncoder().encode(keyStr);
  let k0 = (0xdeadbeef ^ salt) >>> 0;
  let k1 = (0x41c6ce57 ^ Math.imul(salt, 2654435761)) >>> 0;
  let k2 = (0x9e3779b9 ^ bytes.length) >>> 0;
  let k3 = (0x85ebca6b ^ (~salt >>> 0)) >>> 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    k0 = Math.imul(k0 ^ b, 2654435761) >>> 0;
    k1 = Math.imul(k1 ^ b, 2246822519) >>> 0;
    k2 = Math.imul(k2 ^ (b + i), 3266489917) >>> 0;
    k3 = Math.imul(k3 ^ (b << (i & 7)), 668265263) >>> 0;
  }
  const keyCheck = wordKey(k0, k1, k2, k3, (salt ^ 0xa5a5a5a5) >>> 0, 0x7fffffff);
  return { k: [k0, k1, k2, k3], keyCheck };
}

function decryptSlice(u8, startOffset, k, salt) {
  let i = 0;
  const len = u8.byteLength;
  while (i < len && ((startOffset + i) & 3) !== 0) {
    const p = startOffset + i;
    const w = wordKey(k[0], k[1], k[2], k[3], salt, Math.floor(p / 4));
    u8[i] ^= (w >>> ((p & 3) << 3)) & 0xff;
    i++;
  }
  let wordIdx = Math.floor((startOffset + i) / 4);
  while (i + 3 < len) {
    const w = wordKey(k[0], k[1], k[2], k[3], salt, wordIdx++);
    u8[i]     ^= w & 0xff;
    u8[i + 1] ^= (w >>> 8) & 0xff;
    u8[i + 2] ^= (w >>> 16) & 0xff;
    u8[i + 3] ^= (w >>> 24) & 0xff;
    i += 4;
  }
  while (i < len) {
    const p = startOffset + i;
    const w = wordKey(k[0], k[1], k[2], k[3], salt, Math.floor(p / 4));
    u8[i] ^= (w >>> ((p & 3) << 3)) & 0xff;
    i++;
  }
}

function mimeFromCode(c) {
  if (c === 2) return 'video/webm';
  if (c === 3) return 'video/ogg';
  if (c === 4) return 'video/quicktime';
  return 'video/mp4';
}

function parseHeader(buf, keyStr) {
  let hdrOffset = -1;
  if (buf.length >= 56 && buf[24] === 0x53 && buf[25] === 0x56 && buf[26] === 0x49 && buf[27] === 0x44 && buf[28] === 0x32) {
    hdrOffset = 24; // New MP4 ftyp + SVID2 wrapper
  } else if (buf.length >= 32 && buf[0] === 0x53 && buf[1] === 0x56 && buf[2] === 0x49 && buf[3] === 0x44 && buf[4] === 0x32) {
    hdrOffset = 0;  // SVID2 raw
  }
  if (hdrOffset === -1) {
    return { error: 'Invalid file! Yeh locked SVID2 video nahi hai.' };
  }
  const payloadOffset = hdrOffset + 32;
  const dv = new DataView(buf.buffer, buf.byteOffset + hdrOffset, 32);
  const salt = dv.getUint32(8, true);
  const mimeType = mimeFromCode(dv.getUint32(12, true));
  const expectedKeyCheck = dv.getUint32(16, true);
  const origSize = dv.getUint32(24, true) + dv.getUint32(28, true) * 4294967296;
  const { k, keyCheck } = deriveKeys(keyStr, salt);
  if (keyCheck !== expectedKeyCheck) {
    return { error: '⛔ Galat Secret Key! Access Denied.' };
  }
  return { k, salt, mimeType, origSize, payloadOffset };
}

self.addEventListener('message', async (event) => {
  const data = event.data;
  if (!data) return;
  const reply = (payload) => event.ports[0] && event.ports[0].postMessage(payload);

  try {
    if (data.type === 'REGISTER_URL') {
      const res = await fetch(data.url, { headers: { Range: 'bytes=0-55' }, mode: 'cors' });
      if (!res.ok && res.status !== 206) {
        return reply({ ok: false, error: `Server HTTP ${res.status} error!` });
      }
      const buf = new Uint8Array(await res.arrayBuffer()).slice(0, 56);
      const parsed = parseHeader(buf, data.key);
      if (parsed.error) return reply({ ok: false, error: parsed.error });

      const meta = { mode: 'url', url: data.url, ...parsed };
      streams.set(data.id, meta);
      await dbSet(data.id, meta);
      return reply({ ok: true, mimeType: parsed.mimeType, origSize: parsed.origSize });
    }

    if (data.type === 'REGISTER_LOCAL') {
      const file = data.file;
      if (!file || file.size < 33) return reply({ ok: false, error: 'Invalid local file!' });
      const buf = new Uint8Array(await file.slice(0, 56).arrayBuffer());
      const parsed = parseHeader(buf, data.key);
      if (parsed.error) return reply({ ok: false, error: parsed.error });

      const meta = { mode: 'local', file, ...parsed };
      streams.set(data.id, meta);
      await dbSet(data.id, meta);
      return reply({ ok: true, mimeType: parsed.mimeType, origSize: parsed.origSize });
    }
  } catch (err) {
    reply({ ok: false, error: 'CORS ya Network Error! Worker URL aur video link check karein.' });
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (!url.pathname.includes('/svid-stream/')) return;

  const id = url.pathname.split('/svid-stream/')[1];

  event.respondWith((async () => {
    let meta = streams.get(id);
    if (!meta) {
      meta = await dbGet(id);
      if (meta) streams.set(id, meta);
    }
    if (!meta) return new Response('Stream not found', { status: 404 });

    const rangeHdr = event.request.headers.get('Range');
    let start = 0;
    let end = Math.min(MAX_CHUNK - 1, meta.origSize - 1);

    if (rangeHdr) {
      const m = /bytes=(\d+)-(\d*)/.exec(rangeHdr);
      if (m) {
        start = parseInt(m[1], 10);
        const reqEnd = m[2] ? parseInt(m[2], 10) : (start + MAX_CHUNK - 1);
        end = Math.min(reqEnd, start + MAX_CHUNK - 1, meta.origSize - 1);
      }
    }

    if (start >= meta.origSize) {
      return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${meta.origSize}` } });
    }

    const pOff = meta.payloadOffset || 32;
    let u8;
    if (meta.mode === 'local') {
      const sliceBuf = await meta.file.slice(start + pOff, end + pOff + 1).arrayBuffer();
      u8 = new Uint8Array(sliceBuf);
    } else {
      const fetchRes = await fetch(meta.url, {
        headers: { Range: `bytes=${start + pOff}-${end + pOff}` },
        mode: 'cors'
      });
      u8 = new Uint8Array(await fetchRes.arrayBuffer());
    }

    decryptSlice(u8, start, meta.k, meta.salt);

    return new Response(u8, {
      status: 206,
      headers: {
        'Content-Type': meta.mimeType,
        'Accept-Ranges': 'bytes',
        'Content-Range': `bytes ${start}-${start + u8.byteLength - 1}/${meta.origSize}`,
        'Content-Length': String(u8.byteLength),
        'Cache-Control': 'no-store'
      }
    });
  })());
});
