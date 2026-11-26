"""selftest_negative.py — 证明"验不通过时会真的报红"（fail-closed 自测）。

竞品普遍只演示 PASS，不证明 verifier 会抓篡改。本脚本在临时副本上逐项制造篡改，
断言对应检查必须变 FAIL；若某项篡改没被抓到，说明验证器是"永远 PASS 的摆设"。

用法：python3 scripts/selftest_negative.py
退出码：0 = 全部篡改都被抓到；1 = 有漏网。
"""
import json, pathlib, shutil, sys, tempfile, hashlib, datetime as dt

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import verify_min as V  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
KEEP = ["index.json", "attest"]


def fresh_copy():
    d = pathlib.Path(tempfile.mkdtemp(prefix="uibc_neg_"))
    for n in KEEP:
        src = REPO / n
        if src.is_dir():
            shutil.copytree(src, d / n)
        elif src.is_file():
            shutil.copy2(src, d / n)
    return d


def results_map(path):
    res = V.run_checks(path, offline=True)
    return {r["check"]: r["result"] for r in res}


def expect(case, path, must_fail_substring):
    res = results_map(path)
    hit = [k for k, v in res.items() if must_fail_substring in k and v == "FAIL"]
    ok = bool(hit)
    print(f"{'CAUGHT' if ok else 'MISSED':<7} {case:<34} {('命中:' + hit[0]) if ok else '没有任何检查报 FAIL'}")
    return ok


def tamper_index_root(d):
    p = d / "index.json"
    o = json.loads(p.read_text(encoding="utf-8"))
    o["commitments"]["merkle_root"] = "0" * 64
    p.write_text(json.dumps(o, ensure_ascii=False), encoding="utf-8")


def tamper_root_file(d):
    p = d / "attest" / "ROOT.txt"
    b = p.read_bytes().replace(b"root=", b"root=0", 1)
    p.write_bytes(b)


def tamper_continuity_hash(d):
    p = d / "attest" / "CONTINUITY.jsonl"
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    rows[0]["entry_hash"] = "0" * 64
    p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")


def stale_continuity(d):
    p = d / "attest" / "CONTINUITY.jsonl"
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    old = (dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).date() - dt.timedelta(days=30)).isoformat()
    # 重算链，保证"过期但自洽"，专门测停更检测而不是哈希检测
    prev = ""
    for r in rows:
        r["date_local"] = old
        r["prev_entry_hash"] = prev
        body = {k: v for k, v in r.items() if k != "entry_hash"}
        r["entry_hash"] = hashlib.sha256(V.canon(body)).hexdigest()
        prev = r["entry_hash"]
    p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")


def tamper_claim(d):
    p = d / "attest" / "CLAIM.json"
    o = json.loads(p.read_text(encoding="utf-8"))
    o["claim_id"] = "UIBC-IP-TAMPERED"
    p.write_text(json.dumps(o, ensure_ascii=False), encoding="utf-8")


def main():
    ok = True
    cases = [
        ("篡改 index.json 的 merkle_root", tamper_index_root, "ROOT.txt 内 root"),
        ("篡改 ROOT.txt 的 root 行", tamper_root_file, "ROOT.txt sha256"),
        ("篡改连续性 entry_hash", tamper_continuity_hash, "连续性哈希链"),
        ("把连续性台账整体改成 30 天前", stale_continuity, "连续性未停更"),
        ("篡改 CLAIM.json 内容", tamper_claim, "主张签名"),
    ]
    for name, fn, needle in cases:
        d = fresh_copy()
        try:
            fn(d)
            ok = expect(name, d, needle) and ok
        finally:
            shutil.rmtree(d, ignore_errors=True)
    print(f"结论：{'FAIL_CLOSED_OK' if ok else 'LEAK_DETECTED'}（{len(cases)} 个篡改用例）")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
