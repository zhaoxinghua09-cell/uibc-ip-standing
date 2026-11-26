"""make_did.py — 生成 did:web 文档（把主张公钥绑到一个可解析的身份标识）。

did:web:zhaoxinghua09-cell.github.io:uibc-ip-standing
  → 解析 URL：https://zhaoxinghua09-cell.github.io/uibc-ip-standing/did.json

只做一件事：把 attest/CLAIMANT_PUBKEY.pem 的 Ed25519 公钥，以 multibase(base58btc + 0xed01) 形式
写进 DID 文档，并把「DID 标识 → 公钥指纹 → 主张签名」这条对应关系落在 did.json 里。
不新签任何主张（旧主张签名保持原样，不因这份文件而改变）。
"""
import base64, hashlib, json, pathlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
DID_PATH = "uibc-ip-standing"

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def raw_pubkey(pem: bytes) -> bytes:
    """从 SubjectPublicKeyInfo PEM 取出 32 字节 raw 公钥（不依赖 cryptography）。"""
    b64 = b"".join(l.strip() for l in pem.strip().splitlines() if not l.startswith(b"-----"))
    der = base64.b64decode(b64)
    # SPKI: 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
    tail = der[-32:]
    if len(tail) != 32:
        raise ValueError("公钥长度异常")
    return tail


def main():
    pem = (ROOT / "attest" / "CLAIMANT_PUBKEY.pem").read_bytes()
    raw = raw_pubkey(pem)
    fp = hashlib.sha256(pem).hexdigest()
    mb = "z" + b58encode(b"\xed\x01" + raw)
    did = f"did:web:zhaoxinghua09-cell.github.io:{DID_PATH}"
    base = f"https://zhaoxinghua09-cell.github.io/{DID_PATH}/"
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": did + "#claimant-ed25519",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": mb,
        }],
        "authentication": [did + "#claimant-ed25519"],
        "assertionMethod": [did + "#claimant-ed25519"],
        "service": [{
            "id": did + "#evidence",
            "type": "UIBCEvidenceChain",
            "serviceEndpoint": base,
        }],
        "alsoKnownAs": [],
        "uibc": {
            "pem_sha256": fp,
            "claim_id": "UIBC-IP-20261126",
            "note": "本 DID 只绑定公钥与证据入口；不主张法律效力，也不替代 PCC/公证。",
        },
    }
    (ROOT / "did.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    binding = {
        "did": did,
        "resolve_url": base + "did.json",
        "publicKeyMultibase": mb,
        "pem_sha256": fp,
        "raw_key_b64url": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "bound_at_local": None,
        "note": "binding only; the Ed25519 claim signature remains the single source of authorship.",
    }
    (ROOT / "attest" / "DID_BINDING.json").write_text(json.dumps(binding, ensure_ascii=False, indent=2) + "\n",
                                                       encoding="utf-8")
    print(json.dumps({"did": did, "multibase": mb[:24] + "…", "pem_sha256": fp[:16] + "…",
                      "did_json": str(ROOT / "did.json")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
