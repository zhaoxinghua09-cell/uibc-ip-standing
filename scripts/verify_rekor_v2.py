#!/usr/bin/env python3
"""verify_rekor_v2.py —— 离线核对 Rekor v2 条目：签名 + 入证（Merkle）自算。

v2 没有 SET，也没有 "get by index" 的 REST 读接口，所以"这条真在日志里"必须自己算：
  leaf = sha256(0x00 || canonicalizedBody)
  node = sha256(0x01 || left || right)，按 inclusionProof.hashes 自底向上
  结果必须等于 inclusionProof.rootHash

同时核对：canonicalizedBody 里的 digest 是否等于 sha256(attest/ROOT.txt)，
签名是否能用 attest/REKOR_V2_PUBKEY.pem 验通（ECDSA P-256，对摘要直接验，prehashed）。

用法（在仓库根目录）：python scripts/verify_rekor_v2.py
退出码：0 三项全过；1 有不一致
"""
import base64
import hashlib
import json
import pathlib
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key

REPO = pathlib.Path(__file__).resolve().parent.parent
ATTEST = REPO / "attest"


def b64d(x):
    return base64.b64decode(x + "=" * (-len(x) % 4))


def h(b):
    return hashlib.sha256(b).digest()


def leaf_hash(body: bytes) -> bytes:
    return h(b"\x00" + body)


def node(a: bytes, b: bytes) -> bytes:
    return h(b"\x01" + a + b)


def verify_path(leaf: bytes, index: int, size: int, path: list[bytes]) -> bytes:
    cur, idx, sz = leaf, index, size
    for sib in path:
        if idx % 2 == 1 or idx + 1 == sz:
            cur = node(sib, cur)
        else:
            cur = node(cur, sib)
        idx //= 2
        sz = (sz + 1) // 2
    return cur


def main():
    entry = json.loads((ATTEST / "REKOR_V2_ENTRY.json").read_text(encoding="utf-8"))
    e = entry["entry"]
    ip = e["inclusionProof"]
    body = b64d(e["canonicalizedBody"])
    root = b64d(ip["rootHash"])
    path = [b64d(x) for x in ip["hashes"]]
    idx, size = int(ip["logIndex"]), int(ip["treeSize"])

    computed = verify_path(leaf_hash(body), idx, size, path)
    root_ok = computed == root

    spec = json.loads(body)
    digest_in_entry = b64d(spec["spec"]["hashedRekordV002"]["data"]["digest"])
    digest_ok = digest_in_entry == h((ATTEST / "ROOT.txt").read_bytes())

    sig = b64d(spec["spec"]["hashedRekordV002"]["signature"]["content"])
    pk = load_pem_public_key((ATTEST / "REKOR_V2_PUBKEY.pem").read_bytes())
    try:
        pk.verify(sig, digest_in_entry, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        sig_ok = True
    except Exception:  # noqa: BLE001
        sig_ok = False

    out = {
        "checked_at_local": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "log_index": idx,
        "tree_size": size,
        "proof_hashes": len(path),
        "leaf_hash_hex": leaf_hash(body).hex(),
        "root_hash_hex": root.hex(),
        "computed_root_hex": computed.hex(),
        "merkle_root_recomputed": root_ok,
        "digest_matches_roottxt": digest_ok,
        "signature_verifies_with_pubkey": sig_ok,
        "note": "v2 无 SET；integratedTime=0 属正常，时间以 DigiCert RFC3161 为准。",
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if (root_ok and digest_ok and sig_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
