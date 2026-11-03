// Decrypts the Mac build sources (mac-build/payload.b64) with the PAKZ_BUILD_KEY repository secret.
// Format: base64( salt[16] | iv[12] | tag[16] | AES-256-GCM(tar.gz) ), key = scrypt(secret, salt).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { execFileSync } = require('child_process');
const [, , input, outDir] = process.argv;
const dir = path.dirname(input);
const secret = process.env.PAKZ_BUILD_KEY;
if (!secret) { console.error('PAKZ_BUILD_KEY secret is not set'); process.exit(1); }
function decrypt(file) {
  const raw = Buffer.from(fs.readFileSync(file, 'utf8').replace(/\s+/g, ''), 'base64');
  const salt = raw.subarray(0, 16), iv = raw.subarray(16, 28), tag = raw.subarray(28, 44), data = raw.subarray(44);
  const key = crypto.scryptSync(secret, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]);
}
const tgz = decrypt(input);
fs.mkdirSync(outDir, { recursive: true });
const tmp = path.join(outDir, '.payload.tgz');
fs.writeFileSync(tmp, tgz);
execFileSync('tar', ['-xzf', tmp, '-C', outDir], { stdio: 'inherit' });
fs.unlinkSync(tmp);
console.log('unpacked', fs.readdirSync(outDir).join(', '));

// Small follow-up fixes: fix-NNN.b64 = encrypted gzip JSON
// { files: { "rel/path": "new content" | null }, replace: [["rel/path", "old", "new"], ...] }
const fixes = fs.readdirSync(dir).filter(f => /^fix-\d+\.b64$/.test(f)).sort();
for (const f of fixes) {
  const spec = JSON.parse(zlib.gunzipSync(decrypt(path.join(dir, f))).toString('utf8'));
  for (const [rel, content] of Object.entries(spec.files || {})) {
    const p = path.join(outDir, rel);
    if (content === null) fs.rmSync(p, { force: true });
    else { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, content); if (/\.(sh|command)$/.test(p)) fs.chmodSync(p, 0o755); }
  }
  for (const [rel, a, b] of spec.replace || []) {
    const p = path.join(outDir, rel);
    const s = fs.readFileSync(p, 'utf8');
    const n = s.split(a).length - 1;
    if (n !== 1) { console.error(`${f}: expected 1 match in ${rel}, found ${n}`); process.exit(1); }
    fs.writeFileSync(p, s.replace(a, () => b));
  }
  console.log('applied', f);
}
