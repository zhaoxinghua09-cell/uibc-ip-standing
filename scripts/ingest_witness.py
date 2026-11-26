#!/usr/bin/env python3
"""ingest_witness.py（仓库内可审计版本）—— 收一份见证回执：先核，再登记，只增不改。

数值基准取 `attest/WITNESS_RECEIPT_TEMPLATE.json`（该文件每次发布都按当前承诺值重生成，
CI 另有一步死锁"模板根值 == index.json 根值"），因此本脚本不需要接触任何私有材料。

核定五步：
  1) 结构：见证人名称、独立性声明、public_url 必填
  2) 数值：回执的 value_claimed 必须等于模板里的当前值
  3) 自算：填了 value_recomputed 的，必须等于 claimed 且 match=true
  4) 区块：高度拿到 blockstream.info 与 mempool.space 各查一次，两源一致且与 claimed 相符
  5) 登记：通过则追加进台账（seq / 回执 sha256 / prev_entry_hash / entry_hash）

用法（仓库根目录）：
  python scripts/ingest_witness.py <receipt.json> --dry-run
  python scripts/ingest_witness.py <receipt.json> --ledger attest/WITNESS_LEDGER.jsonl
自测回执带 "self-test" 字样时，需 --allow-self-test 才登记，且台账标注 self_test=true。
"""
import argparse
import hashlib
import json
import pathlib
import sys
import time
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
ATTEST = REPO / "attest"
EXPLORERS = {
    "blockstream": "https://blockstream.info/api/block-height/{h}",
    "mempool": "https://mempool.space/api/block-height/{h}",
}


def canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(obj_or_bytes) -> str:
    b = obj_or_bytes if isinstance(obj_or_bytes, bytes) else canon(obj_or_bytes)
    return hashlib.sha256(b).hexdigest()


def get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "uibc-ip-witness/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode().strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--allow-self-test", action="store_true")
    ap.add_argument("--ledger", default=str(ATTEST / "WITNESS_LEDGER.jsonl"))
    args = ap.parse_args()

    tpl = json.loads((ATTEST / "WITNESS_RECEIPT_TEMPLATE.json").read_text(encoding="utf-8"))
    claimed_now = {i["name"]: i["value_claimed"] for i in tpl["items_checked"]}
    idx_root = json.loads((REPO / "index.json").read_text(encoding="utf-8"))["commitments"]["merkle_root"]
    if claimed_now.get("文件集合 Merkle 根") != idx_root:
        print(json.dumps({"error": "回执模板与 index.json 根值不一致，模板已过期"},
                         ensure_ascii=False))
        return 2

    rc = json.loads(pathlib.Path(args.receipt).read_text(encoding="utf-8"))
    w = rc.get("witness") or {}
    problems, checked, blocks = [], {}, {}

    if not str(w.get("name", "")).strip():
        problems.append("缺少见证人名称")
    if not str(w.get("independence_statement", "")).strip():
        problems.append("缺少独立性声明")
    if not str(rc.get("public_url", "")).strip():
        problems.append("缺少 public_url（回执必须可被公开引用）")

    for item in rc.get("items_checked", []):
        name, claimed = item.get("name"), item.get("value_claimed")
        ok_claim = claimed == claimed_now.get(name)
        checked[name] = {"claimed_matches_now": ok_claim}
        if not ok_claim:
            problems.append(f"claimed 与当前值不一致：{name}")
        rec = item.get("value_recomputed")
        if rec not in ("", None):
            ok_rec = rec == claimed
            checked[name]["recomputed_matches_claimed"] = ok_rec
            if not ok_rec:
                problems.append(f"recomputed 与 claimed 不一致：{name}")
        if item.get("match") is False:
            problems.append(f"回执自报不匹配：{name}")

    heights = claimed_now.get("比特币区块高度") or []
    hashes = claimed_now.get("比特币区块哈希") or []
    for i, h in enumerate(heights):
        try:
            got = {k: get(u.format(h=h)) for k, u in EXPLORERS.items()}
        except Exception as e:  # noqa: BLE001
            blocks[str(h)] = {"error": repr(e)}
            problems.append(f"区块 {h} 查询失败：{e}")
            continue
        agree = len(set(got.values())) == 1
        matches = got.get("blockstream") == (hashes[i] if i < len(hashes) else None)
        blocks[str(h)] = {"sources": got, "two_sources_agree": agree, "matches_claim": matches}
        if not (agree and matches):
            problems.append(f"区块 {h} 双源核对未通过")

    verdict = "MATCH" if not problems else "MISMATCH"
    receipt_sha = sha(rc)
    self_test = "self-test" in json.dumps(w, ensure_ascii=False).lower()
    result = {"receipt": args.receipt, "receipt_sha256": receipt_sha, "witness": w.get("name"),
              "checked": checked, "blocks": blocks, "conclusion": verdict,
              "problems": problems, "self_test": self_test, "ledger_appended": False}

    if verdict == "MATCH" and not args.dry_run:
        if self_test and not args.allow_self_test:
            result["problems"].append("自测回执未加 --allow-self-test，拒绝登记")
            result["conclusion"] = "MISMATCH"
        else:
            ledger = pathlib.Path(args.ledger)
            prev, seq = "", 1
            if ledger.exists() and ledger.stat().st_size:
                lines = ledger.read_text(encoding="utf-8").splitlines()
                seq, prev = len(lines) + 1, json.loads(lines[-1]).get("entry_hash", "")
            entry = {"seq": seq, "received_at_local": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                     "request_id": rc.get("request_id", ""), "witness_name": w.get("name", ""),
                     "witness_org": w.get("org", ""), "conclusion": "MATCH",
                     "receipt_sha256": receipt_sha, "prev_entry_hash": prev,
                     "public_url": rc.get("public_url", ""), "self_test": self_test}
            entry["entry_hash"] = sha(dict(entry, entry_hash=None))
            ledger.parent.mkdir(parents=True, exist_ok=True)
            with ledger.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            result.update({"ledger_appended": True, "seq": seq, "entry_hash": entry["entry_hash"],
                           "ledger": str(ledger)})

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["conclusion"] == "MATCH" else 1


if __name__ == "__main__":
    sys.exit(main())
