"""check_continuity.py — CI 侧连续性守门（读 attest/CONTINUITY.jsonl）。

三条：
  1) 每行 entry_hash 必须等于 sha256(canonical_json(去掉 entry_hash))
  2) 下一行 prev_entry_hash 必须等于上一行 entry_hash（首行为空）
  3) 最近一条日期距今不得超过 3 天（停更即报红）
退出码 0 = 通过；非 0 = 失败并打印逐条结果。
"""
import hashlib, json, pathlib, sys, datetime as dt

LEDGER = pathlib.Path(__file__).resolve().parent.parent / "attest" / "CONTINUITY.jsonl"
MAX_AGE_DAYS = 3


def canon(o: dict) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main() -> int:
    if not LEDGER.is_file():
        print("FAIL: attest/CONTINUITY.jsonl 不存在")
        return 1
    rows = [json.loads(l) for l in LEDGER.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not rows:
        print("FAIL: 台账为空")
        return 1
    ok = True
    prev = ""
    for r in rows:
        body = {k: v for k, v in r.items() if k != "entry_hash"}
        h = hashlib.sha256(canon(body)).hexdigest()
        match = (h == r.get("entry_hash"))
        linked = (r.get("prev_entry_hash") == prev)
        print(f"seq={r.get('seq')} date={r.get('date_local')} hash_ok={match} prev_link_ok={linked}")
        ok = ok and match and linked
        prev = r.get("entry_hash")
    dates = sorted(r["date_local"] for r in rows if r.get("date_local"))
    tz8 = dt.timezone(dt.timedelta(hours=8))
    today = dt.datetime.now(tz8).date()
    age = (today - dt.date.fromisoformat(dates[-1])).days
    fresh = age <= MAX_AGE_DAYS
    print(f"entries={len(rows)} first={dates[0]} last={dates[-1]} age_days={age} fresh_ok={fresh}")
    if not ok or not fresh:
        print("结论：FAIL")
        return 1
    print("结论：PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
