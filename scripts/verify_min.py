#!/usr/bin/env python3
"""verify_min.py — 零依赖（仅 Python 3 标准库）复验入口。

为什么再写一个：verify_public.ps1 要 PowerShell、verify.html 要浏览器，而多数第三方 CI 是 Linux + python3。
本脚本只用标准库，一条命令跑完可自动化的检查；Ed25519 验签需要 cryptography，缺库时降级为 WARN（不会假 PASS）。

用法：
  python3 scripts/verify_min.py            # 在仓库根或 scripts/ 下一层执行
  python3 scripts/verify_min.py --offline  # 不联网（跳过 Rekor 在线查）
  python3 scripts/verify_min.py --path /tmp/uibc-ip-standing

退出码：0 = 全部通过（允许 WARN）；1 = 有 FAIL。
"""
import argparse, hashlib, json, pathlib, sys, urllib.request, datetime as dt

RESULTS = []


def add(name, ok, detail="", warn=False):
    RESULTS.append({"check": name, "result": "WARN" if (warn and not ok) else ("PASS" if ok else "FAIL"),
                    "detail": detail})


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def load_json(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))


def parse_root_txt(b):
    out = {}
    for line in b.decode("utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def check_core(repo):
    idx = load_json(repo / "index.json")
    root_bytes = (repo / "attest" / "ROOT.txt").read_bytes()
    root_txt_sha = sha256_bytes(root_bytes)
    want = idx["commitments"]["root_txt_sha256"]
    add("ROOT.txt sha256 == index.json", root_txt_sha == want, f"{root_txt_sha[:16]}… vs {want[:16]}…")

    parsed = parse_root_txt(root_bytes)
    add("ROOT.txt 内 root == index.json merkle_root",
        parsed.get("root") == idx["commitments"]["merkle_root"],
        f"{str(parsed.get('root'))[:16]}…")
    add("ROOT.txt 内 file_count == index.json",
        str(parsed.get("file_count")) == str(idx["commitments"]["file_count"]),
        f"count={parsed.get('file_count')}")
    return idx


def check_continuity(repo, max_age_days=3):
    p = repo / "attest" / "CONTINUITY.jsonl"
    if not p.is_file():
        add("连续性台账存在", False, "attest/CONTINUITY.jsonl 缺失")
        return
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    ok, prev = True, ""
    for r in rows:
        body = {k: v for k, v in r.items() if k != "entry_hash"}
        ok = ok and (sha256_bytes(canon(body)) == r.get("entry_hash")) and (r.get("prev_entry_hash") == prev)
        prev = r.get("entry_hash")
    add("连续性哈希链可重算", ok, f"{len(rows)} 条")
    if rows:
        dates = sorted(r["date_local"] for r in rows if r.get("date_local"))
        age = (dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).date()
               - dt.date.fromisoformat(dates[-1])).days
        add("连续性未停更（≤ %d 天）" % max_age_days, age <= max_age_days,
            f"最近 {dates[-1]}，距今 {age} 天")


def check_signature(repo):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception:
        add("主张签名 Ed25519（需 cryptography）", False, "本机无 cryptography，跳过验签（不是通过）", warn=True)
        return
    try:
        pub = serialization.load_pem_public_key((repo / "attest" / "CLAIMANT_PUBKEY.pem").read_bytes())
        claim = load_json(repo / "attest" / "CLAIM.json")
        import base64
        sig = base64.b64decode((repo / "attest" / "CLAIM.json.sig").read_text(encoding="utf-8").strip())
        payload = canon(claim)
        pub.verify(sig, payload)
        add("主张签名 Ed25519", True, f"规范字节 sha256={sha256_bytes(payload)[:16]}…")
    except Exception as e:
        add("主张签名 Ed25519", False, f"{type(e).__name__}: {str(e)[:80]}")


def check_rekor(repo, offline):
    if offline:
        add("Rekor v1 在线在册（--offline 跳过）", False, "已跳过，未在线核实", warn=True)
        return
    uuid = None
    try:
        uuid = load_json(repo / "attest" / "REKOR_PROOF.json")["uuid"]
    except Exception:
        pass
    if not uuid:
        add("Rekor v1 在线在册", False, "attest/REKOR_PROOF.json 里没有 uuid")
        return
    url = "https://rekor.sigstore.dev/api/v1/log/entries/" + uuid
    try:
        with urllib.request.urlopen(url, timeout=25) as r:
            body = r.read()
        entry = json.loads(body)
        li = list(entry.values())[0]["logIndex"]
        add("Rekor v1 在线在册", True, f"logIndex={li}")
    except Exception as e:
        add("Rekor v1 在线在册", False, f"{type(e).__name__}: {str(e)[:80]}")


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + b


def check_did(repo, offline):
    """did:web 文档必须绑定同一把主张公钥（多基解码后逐字节比对）。"""
    import base64
    p = repo / "did.json"
    if not p.is_file():
        add("DID 文档存在", False, "did.json 缺失")
        return
    doc = load_json(p)
    vm = (doc.get("verificationMethod") or [{}])[0]
    mb = vm.get("publicKeyMultibase") or ""
    try:
        raw = b58decode(mb[1:])[2:]  # 去掉 multibase 前缀 'z' 与 multicodec 0xed01
    except Exception as e:
        add("DID 公钥可解码", False, f"{type(e).__name__}: {str(e)[:60]}")
        return
    pem = (repo / "attest" / "CLAIMANT_PUBKEY.pem").read_bytes()
    b64 = b"".join(l.strip() for l in pem.strip().splitlines() if not l.startswith(b"-----"))
    der_raw = base64.b64decode(b64)[-32:]
    ok = raw == der_raw
    add("DID 公钥 == CLAIMANT_PUBKEY.pem", ok, f"multibase={mb[:18]}…")
    add("DID 记录的 pem_sha256 一致",
        (doc.get("uibc") or {}).get("pem_sha256") == sha256_bytes(pem),
        "did.json.uibc.pem_sha256")
    if offline:
        add("DID 可解析（--offline 跳过）", False, "已跳过，未在线解析", warn=True)
        return
    try:
        with urllib.request.urlopen((doc.get("service") or [{}])[0].get("serviceEndpoint", "") + "did.json",
                                    timeout=20) as r:
            live = json.loads(r.read())
        add("DID 在线解析且 ID 一致", live.get("id") == doc.get("id"), str(doc.get("id"))[:40])
    except Exception as e:
        add("DID 在线解析", False, f"{type(e).__name__}: {str(e)[:60]}")


def run_checks(repo, offline=False):
    """跑全部检查并返回结果列表（供 selftest_negative.py 之类的程序化调用）。"""
    del RESULTS[:]
    try:
        check_core(repo)
        check_continuity(repo)
        check_signature(repo)
        check_did(repo, offline)
        check_rekor(repo, offline)
    except Exception as e:
        add("脚本异常", False, f"{type(e).__name__}: {str(e)[:100]}")
    return list(RESULTS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=None)
    ap.add_argument("--offline", action="store_true")
    a = ap.parse_args()
    repo = pathlib.Path(a.path).resolve() if a.path else pathlib.Path(__file__).resolve().parent.parent
    res = run_checks(repo, a.offline)
    fails = [r for r in res if r["result"] == "FAIL"]
    for r in res:
        print(f"{r['result']:<4} {r['check']}  {r['detail']}")
    print(f"结论：{'FAIL' if fails else 'PASS'}（{len(res) - len(fails)} 项通过/警告，{len(fails)} 项失败）")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
