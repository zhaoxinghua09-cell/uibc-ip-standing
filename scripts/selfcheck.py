#!/usr/bin/env python3
"""自检：本仓库的承诺件有没有被改动过。

零网络、只读。检查项：
  1) PUBLISHED_SHA256SUMS.txt 里每个文件的 sha256 与磁盘一致
  2) attest/ROOT.txt 的 sha256 == PUBLICATION.json.subject.root_txt_sha256 == index.json.commitments.root_txt_sha256
  3) CLAIM.json 的规范字节签名验签通过（需 cryptography）
  4) PUBLICATION.json 与 index.json 的根、主张指纹、签名摘要三项一致

退出码：0 通过；1 不一致。
用法：python scripts/selfcheck.py
"""
import base64
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
fail = []


def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def load(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))


# 1) 逐文件哈希
sums = ROOT / "PUBLISHED_SHA256SUMS.txt"
if sums.exists():
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        want, rel = line.split("  ", 1)
        p = ROOT / rel
        if not p.exists():
            fail.append(f"missing: {rel}")
        elif sha256(p) != want:
            fail.append(f"changed: {rel}")
else:
    fail.append("missing: PUBLISHED_SHA256SUMS.txt")

pub = load(ROOT / "PUBLICATION.json")
idx = load(ROOT / "index.json")

# 2) ROOT.txt 三处一致
rt = sha256(ROOT / "attest" / "ROOT.txt")
for name, val in (
    ("disk", rt),
    ("PUBLICATION", pub["subject"]["root_txt_sha256"]),
    ("index.json", idx["commitments"]["root_txt_sha256"]),
):
    if val != rt:
        fail.append(f"root_txt_sha256 mismatch at {name}: {val} != {rt}")

# 3) 主张签名
try:
    from cryptography.hazmat.primitives import serialization

    pk = serialization.load_pem_public_key((ROOT / "attest" / "CLAIMANT_PUBKEY.pem").read_bytes())
    body = json.dumps(
        load(ROOT / "attest" / "CLAIM.json"),
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    payload_sha = hashlib.sha256(body).hexdigest()
    if payload_sha != pub["claim"]["signed_payload_sha256"]:
        fail.append(f"canonical payload sha256 {payload_sha} != PUBLICATION 记载")
    sig = base64.b64decode((ROOT / "attest" / "CLAIM.json.sig").read_text(encoding="utf-8").strip())
    pk.verify(sig, body)
except ImportError:
    print("WARN: cryptography 未安装，跳过签名验签（degraded）")
except Exception as e:
    fail.append(f"signature verify failed: {e!r}")

# 4) 跨文件三项一致
if pub["subject"]["merkle_root"] != idx["commitments"]["merkle_root"]:
    fail.append("merkle_root: PUBLICATION != index.json")
if pub["claim"]["claimant_pubkey_fingerprint_sha256"] != idx["commitments"]["claim_pubkey_fingerprint"]:
    fail.append("claim fingerprint: PUBLICATION != index.json")
if pub["claim"]["claim_signature_sha256"] != idx["commitments"]["claim_signature_sha256"]:
    fail.append("claim signature sha256: PUBLICATION != index.json")
if pub["rfc3161"]["imprint_matches_root_txt"] is not True:
    fail.append("rfc3161 imprint_matches_root_txt 不是 true")

print(f"files checked: {len(sums.read_text(encoding='utf-8').splitlines()) if sums.exists() else 0}")
if fail:
    print("RESULT: FAILED")
    for f in fail:
        print("  -", f)
    sys.exit(1)
print("RESULT: OK（承诺件与 PUBLICATION 一致，签名验签通过）")
