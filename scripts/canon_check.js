// canon_check.js —— 校验“浏览器内复验页”用的规范化算法与仓内承诺值一致
// 用途：CI 上跑一遍，防止有人改了 CLAIM.json 的字段顺序/数值却没重签，
//       或 verify.html 的规范字节算法与 Python(json.dumps sort_keys...) 漂移。
//
// 用法：node scripts/canon_check.js attest/CLAIM.json attest/CLAIM.json.sig attest/CLAIMANT_PUBKEY.pem
// 退出码：0 一致；1 不一致

const fs = require('fs');
const crypto = require('crypto');

function canon(v) {                                  // 等价 Python: sort_keys=True, separators=(",",":"), ensure_ascii=False
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

const [claimPath, sigPath, pemPath] = process.argv.slice(2);
if (!claimPath || !sigPath || !pemPath) { console.error('用法: node scripts/canon_check.js <CLAIM.json> <CLAIM.json.sig> <PUBKEY.pem>'); process.exit(1); }

const claim = JSON.parse(fs.readFileSync(claimPath, 'utf8'));
const body = Buffer.from(canon(claim), 'utf8');
const payloadHash = crypto.createHash('sha256').update(body).digest('hex');
const key = crypto.createPublicKey(fs.readFileSync(pemPath, 'utf8'));
const sig = Buffer.from(fs.readFileSync(sigPath, 'utf8').replace(/\s+/g, ''), 'base64');
const sigOk = crypto.verify(null, body, key, sig);
const fp = crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');

const pub = JSON.parse(fs.readFileSync('PUBLICATION.json', 'utf8'));
const wantPayload = (pub.claim || {}).signed_payload_sha256;
const wantFp = (pub.claim || {}).claimant_pubkey_fingerprint_sha256;

console.log('signed_payload_sha256 =', payloadHash);
console.log('signature_verify      =', sigOk);
console.log('pubkey_fingerprint    =', fp);

const fail = [];
if (!sigOk) fail.push('签名验签失败');
if (wantPayload && wantPayload !== payloadHash) fail.push(`规范字节 sha256 与 PUBLICATION 不一致（承诺 ${wantPayload}）`);
if (wantFp && wantFp !== fp) fail.push(`公钥指纹与 PUBLICATION 不一致（承诺 ${wantFp}）`);

if (fail.length) { fail.forEach(f => console.log('FAIL: ' + f)); process.exit(1); }
console.log('RESULT: OK（规范字节与签名、公钥指纹均与 PUBLICATION 一致）');
