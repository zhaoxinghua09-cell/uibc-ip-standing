"""verify_offline.py — 零依赖版复验器（只用 Python 标准库，不装 cryptography 也能跑）。

解决的问题：`verify_pack.py` 需要 cryptography/ots 才能验 RFC3161 与 OTS，外人拿到包常缺依赖。
本脚本把"结构自洽 + 摘要一致 + 哈希链完整 + 区块头自校"这些**纯算术**部分做完全，
把所有需要第三方库的检查显式降级标注（degraded），绝不把"没验"说成"验过"。

用法：python verify_offline.py [包根目录]
输出：JSON，含 grade（VERIFIED_STRUCTURE / PROBLEMS）、checks、degraded（未做/降级的项及原因）。
"""
import hashlib, json, pathlib, re, subprocess, sys

PKG = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path.cwd()


def leaf(h):
    return hashlib.sha256(b"uibc-ip-leaf\n" + h.encode()).hexdigest()


def node(a, b):
    return hashlib.sha256(b"uibc-ip-node\n" + a.encode() + b.encode()).hexdigest()


def merkle(hashes):
    layer = [leaf(h) for h in hashes]
    depth = 0
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [node(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        depth += 1
    return layer[0], depth


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def load(p, default=None):
    p = pathlib.Path(p)
    if not p.is_file():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def main():
    problems, checks, degraded = [], {}, []
    out = PKG / "out"
    man = load(out / "MANIFEST.json")
    rootp = out / "ROOT.txt"
    if not man or not rootp.is_file():
        print(json.dumps({"grade": "PACK_INCOMPLETE", "reason": "缺 MANIFEST.json 或 ROOT.txt"}, ensure_ascii=False))
        return 2
    root_txt = rootp.read_text(encoding="utf-8")

    # 1) 清单 → Merkle 根（纯算术）
    recomputed, depth = merkle([f["sha256"] for f in man["files"]])
    checks["manifest_count"] = man["count"]
    checks["recomputed_merkle_root"] = recomputed
    checks["depth"] = depth
    if recomputed != (man.get("merkle") or {}).get("root"):
        problems.append("manifest 重算 Merkle 根与 manifest 记载不符")
    if f"root={recomputed}" not in root_txt:
        problems.append("ROOT.txt 未记载重算出的根")

    # 2) ROOT.txt 字节哈希
    rt_sha = sha256_file(rootp)
    checks["root_txt_sha256"] = rt_sha
    pkg_man = load(PKG / "manifest.json", {}) or {}
    if (pkg_man.get("claim") or {}).get("root_txt_sha256"):
        if pkg_man["claim"]["root_txt_sha256"] != rt_sha:
            problems.append("ROOT.txt 哈希与 manifest.json claim 不符")

    # 3) 区块头自校（sha256d + header 内 merkle root，纯算术）
    hd = out / "btc_headers"
    header_roots = set()
    if hd.is_dir():
        n, bad = 0, 0
        for f in sorted(hd.glob("*.json")):
            r = json.loads(f.read_text(encoding="utf-8"))
            raw = bytes.fromhex(r.get("header_hex", ""))
            if len(raw) != 80:
                bad += 1
                problems.append(f"区块头长度异常 {f.name}")
                continue
            sha = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
            mr = raw[36:68][::-1].hex()
            header_roots.add(mr)
            n += 1
            if sha != r.get("block_hash") or mr != r.get("merkle_root_from_header"):
                bad += 1
                problems.append(f"区块头自校失败 {r.get('height')}-{r.get('source')}")
        checks["btc_headers"] = {"files": n, "bad": bad}

    # 4) 索引台账行级链
    led = out / "INDEX_LEDGER.jsonl"
    if led.is_file():
        rows = [json.loads(l) for l in led.read_text(encoding="utf-8").splitlines() if l.strip()]
        okc = True
        for i, r in enumerate(rows):
            payload = {k: v for k, v in r.items() if k != "entry_hash"}
            want = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()
            if want != r.get("entry_hash") or r.get("prev_entry_hash") != (rows[i - 1]["entry_hash"] if i else None):
                okc = False
        checks["index_ledger"] = {"entries": len(rows), "chain_ok": okc}
        if not okc:
            problems.append("INDEX_LEDGER.jsonl 行级链断裂")
    else:
        degraded.append({"item": "索引台账", "reason": "包内无 INDEX_LEDGER.jsonl"})

    # 5) 审计日志链 + 日志承诺
    log = PKG / "anchor_log.jsonl"
    if log.is_file():
        raw = log.read_bytes().split(b"\n")
        while raw and not raw[-1].strip():
            raw.pop()
        head = hashlib.sha256(raw[-1]).hexdigest()
        checks["log_lines"] = len(raw)
        ch = load(out / "ANCHOR_LOG_CHAIN.json", {}) or {}
        if ch.get("last_line_sha256") and ch["last_line_sha256"] != head:
            problems.append("日志末行与链头记录不符")
        commit = out / "ROOT-LOG.txt"
        if commit.is_file():
            m = re.search(r"head_sha256=([0-9a-f]{64})", commit.read_text(encoding="utf-8", errors="replace"))
            if m and m.group(1) != head:
                problems.append("ROOT-LOG.txt 承诺链头与日志末行不符")
            checks["log_commitment_head"] = m.group(1) if m else None

    # 6) 主张绑定（只核摘要一致，不验签名——纯库做不到 Ed25519 验签）
    claim = load(out / "CLAIM.json", {}) or {}
    if claim:
        subj = claim.get("subject") or {}
        if subj.get("merkle_root") != recomputed:
            problems.append("CLAIM.json 绑定的根与重算根不符")
        checks["claim_bound_root"] = subj.get("merkle_root")
        sigp = out / "CLAIM.json.sig"
        ca = load(out / "CLAIM_ANCHOR.json", {}) or {}
        if sigp.is_file():
            sig_sha = hashlib.sha256(sigp.read_bytes()).hexdigest()
            checks["claim_signature_sha256"] = sig_sha
            if ca.get("signature_file_sha256"):
                if ca["signature_file_sha256"] != sig_sha:
                    problems.append("CLAIM.json.sig 字节与 CLAIM_ANCHOR 记录不符（签名文件被替换）")
        degraded.append({"item": "Ed25519 主张签名验签",
                          "reason": "纯标准库无法验 Ed25519；请用 verify_pack.py（需 cryptography）"})

    # 7) RFC3161 imprint 一致性（不验签名/链）
    tsa = load(out / "TSA.json", {}) or {}
    if (out / "root.tsr").is_file():
        if tsa.get("root_sha512"):
            if tsa["root_sha512"] != hashlib.sha512(rootp.read_bytes()).hexdigest():
                problems.append("TSA.json 记录的 imprint 与独立计算的 sha512(ROOT.txt) 不符")
            checks["tsa_imprint_matches_computed"] = True
        degraded.append({"item": "RFC3161 签名与证书链",
                          "reason": "需 cryptography（或验签实现）；请用 verify_pack.py"})

    # 7b) 签名树头（STH）：纯算术重算树根 + 尺寸，签名本身需 cryptography（降级）
    sth_p = out / "STH.txt"
    if sth_p.is_file() and led.is_file():
        import base64
        lines = sth_p.read_text(encoding="utf-8").split("\n")
        try:
            size = int(lines[1])
            root_b64 = lines[2].strip()
            sth_root_b64 = root_b64
            # 独立重算（域分隔与 sth.py 一致）
            def s_leaf(h):
                return hashlib.sha256(b"uibc-sth-leaf\n" + h.encode()).hexdigest()

            def s_node(a, b):
                return hashlib.sha256(b"uibc-sth-node\n" + a.encode() + b.encode()).hexdigest()

            layer = [s_leaf(r["entry_hash"]) for r in rows] or [s_leaf("")]
            while len(layer) > 1:
                if len(layer) % 2:
                    layer.append(layer[-1])
                layer = [s_node(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
            rec_root = base64.b64encode(bytes.fromhex(layer[0])).decode()
            checks["sth"] = {"tree_size": size, "size_matches_ledger": size == len(rows),
                             "root_matches_recomputed": rec_root == sth_root_b64}
            if size != len(rows) or rec_root != sth_root_b64:
                problems.append("STH 树根/尺寸与台账重算不符（树头与台账不一致）")
        except Exception as e:
            problems.append(f"STH 解析失败：{type(e).__name__}")
        degraded.append({"item": "STH 签名验签", "reason": "Ed25519 需 cryptography；请用 verify_pack.py"})

    # 8) OTS 证明（若本机有 ots 工具则核 heights/roots，否则降级）
    ots_p = out / "ROOT.txt.ots"
    anchors = load(out / "ANCHORS.json", {}) or {}
    if ots_p.is_file():
        try:
            info = subprocess.run(["ots", "info", str(ots_p)], capture_output=True, text=True,
                                  encoding="utf-8", timeout=60)
            text = (info.stdout or "") + (info.stderr or "")
            hts = sorted({int(m) for m in re.findall(r"BitcoinBlockHeaderAttestation\((\d+)\)", text)})
            roots = {m.lower() for m in re.findall(r"Bitcoin block merkle root ([0-9a-fA-F]{64})", text)}
            checks["ots_heights_in_proof"] = hts
            if anchors.get("heights_in_proof") and set(anchors["heights_in_proof"]) != set(hts):
                problems.append("ANCHORS.json 高度与 .ots 不一致")
            missing = [mr for mr in header_roots if mr not in roots]
            if missing:
                problems.append(f"{len(missing)} 个区块头 merkle root 不在 .ots 证明内")
            checks["ots_merkle_roots_match_headers"] = True
        except Exception as e:
            degraded.append({"item": "OTS 证明结构核对", "reason": f"本机无 ots 工具或执行失败（{type(e).__name__}）"})
    else:
        problems.append("包内缺 ROOT.txt.ots")

    degraded.append({"item": "比特币区块头是否在最长链", "reason": "需联网或节点；请按 ANCHORS.json 高度到公共浏览器核对"})

    grade = "VERIFIED_STRUCTURE" if not problems else "PROBLEMS"
    print(json.dumps({"pack": str(PKG), "grade": grade, "checks": checks, "problems": problems,
                      "degraded": degraded,
                      "note": "本脚本不依赖第三方库，验的是'结构与摘要自洽'；签名级验证请用 verify_pack.py"},
                     ensure_ascii=False, indent=1))
    return 0 if not problems else 2


if __name__ == "__main__":
    sys.exit(main())
