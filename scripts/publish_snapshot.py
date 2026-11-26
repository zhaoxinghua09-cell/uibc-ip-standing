#!/usr/bin/env python3
"""把证据链最新承诺刷新进本仓库并发布（一次命令）。

做的事：
  1) 从 <ip 工作副本>/out 复制白名单内的承诺件到 attest/（白名单见 ATTEST_FILES）
  2) 重写 PUBLICATION.json 的数值（根、区块、TSA、主张、日志链头、台账、STH、守卫）
  3) 刷新 index.html / index.json、PUBLISHED_SHA256SUMS.txt
  4) 跑 scripts/selfcheck.py；通过后（--commit）提交并按需推送

不碰：证据本体、私钥、文件清单、令牌原始件（见 PUBLISH_SCOPE.md）。

用法：
  python scripts/publish_snapshot.py --src "D:/Workbuddy/回家同步/IP证据链_20261126/work/ip" --dry-run
  python scripts/publish_snapshot.py --src <同上> --commit --push --note "每日巡检刷新"
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

ATTEST_FILES = [
    "ROOT.txt", "ROOT.txt.ots",
    "ROOT-LOG.txt", "ROOT-LOG.txt.ots",
    "INDEX-LEDGER.txt", "INDEX-LEDGER.txt.ots",
    "INDEX_LEDGER.jsonl", "STH.json", "ANCHORS.json",
    "TSA.json", "TSA_GUARD.json", "TSA_PIN_BASELINE.json",
    "CLAIM.json", "CLAIM.json.sig",
    "CLAIMANT_PUBKEY.pem", "CLAIMANT_FINGERPRINT.txt",
    "CLAIM_ANCHOR.json", "CLAIM_VERIFY.json",
    "IP_VERIFY.json", "HEALTH.md", "RECHECK_SCHEDULE.json",
    "WITNESS_KIT.md", "WITNESS_REQUEST.json",
    "WITNESS_RECEIPT_TEMPLATE.json", "WITNESS_LEDGER_SCHEMA.json",
    "REKOR_PROOF.json", "REPO_WATCH.json",
    "REKOR_V2_ENTRY.json", "REKOR_V2_VERIFY.json", "REKOR_V2_PUBKEY.pem",
    "REKOR_V2_CHECKPOINT.txt",
    "CONTINUITY.jsonl", "CONTINUITY.json",
]


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    return sha256_bytes(pathlib.Path(p).read_bytes())


def load(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="ip 工作副本目录（含 out/）")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--commit", action="store_true")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--note", default="")
    args = ap.parse_args()

    src = pathlib.Path(args.src)
    out = src / "out"
    if not (out / "ROOT.txt").exists():
        sys.exit(f"FATAL: {out}/ROOT.txt 不存在，--src 指错了？")

    log = []

    # 1) 复制承诺件
    for name in ATTEST_FILES:
        s = out / name
        if not s.exists():
            sys.exit(f"FATAL: 缺少承诺件 {name}")
        shutil.copy2(s, REPO / "attest" / name)

    # 主张签名版本文件：按 CLAIM_ANCHOR 记载的 signature_sha256 前 12 位取；先清掉旧版本，避免仓里留过期签名
    for old in list((REPO / "attest").glob("CLAIM-SIG-*.txt*")):
        old.unlink()
    anchor = load(out / "CLAIM_ANCHOR.json")
    sig12 = anchor["signature_sha256"][:12]
    for suf in ("", ".ots"):
        s = out / f"CLAIM-SIG-{sig12}.txt{suf}"
        if not s.exists():
            sys.exit(f"FATAL: 缺少签名承诺件 {s.name}")
        shutil.copy2(s, REPO / "attest" / s.name)

    # STH 的 .ots：文件名带 root 前缀
    sth = load(out / "STH.json")
    sth_ots = out / f"STH-{sth['root_hash'][:12]}.txt.ots"
    if sth_ots.exists():
        shutil.copy2(sth_ots, REPO / "attest" / sth_ots.name)

    # 2) 重写 PUBLICATION.json
    pub = load(REPO / "PUBLICATION.json")
    ipv = load(out / "IP_VERIFY.json")
    la = load(out / "LOG_ANCHOR.json")
    il = load(out / "INDEX_LEDGER.json")
    cv = load(out / "CLAIM_VERIFY.json")
    tsa = load(out / "TSA.json")
    guard = load(out / "TSA_GUARD.json")
    sched = load(out / "RECHECK_SCHEDULE.json")

    pub["published_at_local"] = datetime.datetime.now().strftime("%Y-%m-%d")
    pub["subject"]["files"] = ipv["count"]
    pub["subject"]["merkle_root"] = ipv["merkle_root"]
    pub["subject"]["depth"] = ipv["depth"]
    pub["subject"]["root_txt_sha256"] = sha256_file(REPO / "attest" / "ROOT.txt")

    blocks = []
    anchors_full = load(out / "ANCHORS.json")
    merkle_by_height = {b["height"]: b.get("merkle_root", "") for b in anchors_full.get("blocks", [])}
    for b in ipv["anchors"]["opentimestamps"]["blocks"]:
        blocks.append({
            "height": b["height"], "block_hash": b["block_hash"],
            "merkle_root": merkle_by_height.get(b["height"], b.get("merkle_root", "")),
            "gen_time_utc": b["gen_time_utc"],
            "sources_agree": b.get("sources_agree", True),
            "sources": b.get("matched_sources", ["blockstream", "mempool"]),
        })
    pub["bitcoin_anchors"] = blocks

    pub["rfc3161"].update({
        "tsa": tsa["tsa_name"],
        "gen_time_utc": tsa["gen_time_utc"],
        "gen_time_original_field": tsa["gen_time_utc"],
        "hash_algorithm": tsa["hash_algorithm"],
        "imprint_sha512": tsa["root_sha512"],
        "imprint_matches_root_txt": tsa["imprint_matches"],
        "chain_verified": tsa["chain_verified"],
        "top_subject": tsa["chain_detail"]["top_subject"],
        "top_in_public_roots": tsa["chain_detail"]["top_in_public_roots"],
    })
    pub["rfc3161"]["redundancy"] = {
        "verified_tsas": guard["checks"]["verified_tsas"],
        "verified_with_public_root": guard["checks"]["verified_with_public_root"],
        "names": [r["tsa"] for r in tsa.get("redundancy", [])],
    }

    pub["claim"].update({
        "claim_id": cv["claim_id"],
        "claimant_pubkey_fingerprint_sha256": cv["pubkey_fingerprint_sha256"],
        "claim_signature_sha256": anchor["signature_sha256"],
        "signature_file": f"attest/CLAIM-SIG-{sig12}.txt",
        "signed_payload_sha256": cv["signed_payload_sha256"],
        "signature_ok": cv["signature_ok"],
        "claim_reused": cv["claim_reused"],
    })
    pub["audit_log"] = {
        "lines": la["current_lines"],
        "head_sha256": la["current_head"],
        "log_file_sha256": la["log_file_sha256_at_anchor"],
        "anchor_status": la["status"],
    }
    pub["index_ledger"] = {"entries": il["entries"], "head_entry_hash": il["head_entry_hash"]}
    pub["sth"] = {
        "log_id": sth["log_id"], "tree_size": sth["tree_size"],
        "root_hash": sth["root_hash"], "root_b64": sth["root_b64"],
        "signature_scheme": sth["signature_scheme"], "anchor_status": sth["anchor_status"],
    }
    pub["tsa_guard"] = {
        "level": guard["level"],
        "ocsp_verified": guard["checks"]["ocsp"]["verified"],
        "crls": len(list((out / "tsa_ltv").glob("*/*.crl"))) if (out / "tsa_ltv").exists() else pub["tsa_guard"]["crls"],
        "earliest_recheck_by": sched.get("earliest_recheck_by", pub["tsa_guard"]["earliest_recheck_by"]),
    }

    # 3) 索引页：先让证据链侧重生成（避免用过期索引），再复制
    gen = src / "public_index.py"
    if gen.exists():
        r = subprocess.run([sys.executable, str(gen)], cwd=str(src), capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"FATAL: public_index.py 生成失败：{r.stderr[-500:]}")
    # 证书页：同样由证据链侧生成（依赖 PUBLICATION.json）
    certgen = src / "make_certificate.py"
    if certgen.exists():
        r = subprocess.run([sys.executable, str(certgen)], cwd=str(src), capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"FATAL: make_certificate.py 生成失败：{r.stderr[-500:]}")
    # 见证回执模板：必须按当前数值重生成，否则见证人会核出假阴性
    witgen = src / "make_witness_template.py"
    if witgen.exists():
        r = subprocess.run([sys.executable, str(witgen)], cwd=str(src), capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"FATAL: make_witness_template.py 生成失败：{r.stderr[-500:]}")
    # 连续性台账：先跑心跳（幂等，同一天同一快照不重复写），再生成页面
    for gen_name in ("heartbeat.py", "make_continuity.py"):
        g = src / gen_name
        if g.exists():
            r = subprocess.run([sys.executable, str(g)], cwd=str(src), capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit(f"FATAL: {gen_name} 失败：{r.stderr[-500:]}")

    for n in ("index.html", "index.json", "certificate.html", "continuity.html"):
        p = out / "public_index" / n
        if p.exists():
            shutil.copy2(p, REPO / n)

    # 3b) 报告：复制并脱敏本机路径/主机名（报告不是签名产物，可改）
    report = src / "IP外锚与存证_竞品与最佳实践矩阵_20261126.md"
    if report.exists():
        text = report.read_text(encoding="utf-8")
        for k, v in (
            (str(src), "<工作目录>"),
            ("C:\\Users\\SZYL\\Doubao\\chats\\2026-11-23\\new-chat-14\\ip", "<工作目录>"),
            ("C:\\Users\\SZYL", "<用户目录>"),
            ("DESKTOP-IGJBTUB", "<主机A>"),
            ("赵兴华的台式机", "<主机B>"),
        ):
            text = text.replace(k, v)
        (REPO / "docs" / "对标与实测报告_20261126.md").write_text(text, encoding="utf-8")

    if args.dry_run:
        print("DRY-RUN：以下数值将被写入（不落盘）")
        print(f"  files={pub['subject']['files']} root={pub['subject']['merkle_root'][:16]}…")
        print(f"  log_head={pub['audit_log']['head_sha256'][:16]}… lines={pub['audit_log']['lines']} status={pub['audit_log']['anchor_status']}")
        print(f"  ledger_entries={pub['index_ledger']['entries']} sth_size={pub['sth']['tree_size']}")
        print(f"  blocks={[b['height'] for b in blocks]}")
        return

    (REPO / "PUBLICATION.json").write_text(
        json.dumps(pub, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 4) 哈希清单 + 自检
    lines = []
    for p in sorted(REPO.rglob("*")):
        if p.is_dir() or ".git" in p.parts or p.name == "PUBLISHED_SHA256SUMS.txt":
            continue
        lines.append(f"{sha256_file(p)}  {p.relative_to(REPO).as_posix()}")
    (REPO / "PUBLISHED_SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    r = subprocess.run([sys.executable, str(REPO / "scripts" / "selfcheck.py")])
    if r.returncode != 0:
        sys.exit("FATAL: selfcheck 未通过，不提交")

    if args.commit:
        git = shutil.which("git") or r"C:\Program Files\Git\cmd\git.exe"
        msg = f"PUB {pub['published_at_local']}: {pub['subject']['files']} 文件 root={pub['subject']['merkle_root'][:12]} 日志行={pub['audit_log']['lines']}"
        if args.note:
            msg += f" / {args.note}"
        subprocess.run([git, "-C", str(REPO), "add", "-A"], check=True)
        subprocess.run([git, "-C", str(REPO), "commit", "-q", "-m", msg], check=True)
        log.append("committed: " + subprocess.run(
            [git, "-C", str(REPO), "log", "--oneline", "-1"],
            capture_output=True, text=True).stdout.strip())
        if args.push:
            subprocess.run([git, "-C", str(REPO), "push", "origin", "main"], check=True)
            log.append("pushed: origin/main")

    print("OK")
    for l in log:
        print("  " + l)


if __name__ == "__main__":
    main()
