"""verify_pack.py — 只用**证据包内**的文件复验整条权属链，不依赖原始 2683 个产物，不联网。

与 verify_ip.py 的分工：
  verify_ip.py  —— 在制作现场，有全部原始文件，逐文件重算 sha256
  verify_pack.py —— 外人拿到 zip：只有 manifest / ROOT.txt / 令牌 / 证书 / CRL，
                    验"清单与根是否自洽"、"令牌是否真的签在这份根上"

复验四步：
  1) 清单自洽：用 MANIFEST.json 的逐文件 sha256 重算 Merkle 根，与 ROOT.txt 内记载的 root 比对
  2) ROOT.txt 字节哈希 = manifest.claim.root_txt_sha256
  3) RFC3161：令牌 imprint 必等于本脚本独立计算的 ROOT.txt 摘要；签名与证书链须验过（tsa_verify）
  4) OpenTimestamps：证明文件在包内，且 ANCHORS.json 记录的区块高度/merkle root 与 .ots 内 attestation 一致
用法：python verify_pack.py [包根目录]（默认当前目录）
边界：本脚本不重算原始文件（包内没有原始产物）；不联网，因此不复核区块头（需外部浏览器或节点）。
"""
import hashlib, json, pathlib, re, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
PKG = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE

def leaf(h): return hashlib.sha256(b"uibc-ip-leaf\n" + h.encode()).hexdigest()
def node(a, b): return hashlib.sha256(b"uibc-ip-node\n" + a.encode() + b.encode()).hexdigest()

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

def main():
    problems, checks = [], {}
    man_path = PKG / "out" / "MANIFEST.json"
    root_path = PKG / "out" / "ROOT.txt"
    if not man_path.is_file() or not root_path.is_file():
        print(json.dumps({"verdict": "PACK_INCOMPLETE", "reason": "缺 MANIFEST.json 或 ROOT.txt"}, ensure_ascii=False))
        return 2
    man = json.loads(man_path.read_text(encoding="utf-8"))
    root_txt = root_path.read_text(encoding="utf-8")
    root_bytes = root_path.read_bytes()

    # 1) 清单自洽 → Merkle 根
    recomputed, depth = merkle([f["sha256"] for f in man["files"]])
    checks["manifest_count"] = man["count"]
    checks["recomputed_merkle_root"] = recomputed
    checks["depth"] = depth
    if recomputed != man["merkle"]["root"]:
        problems.append("manifest 逐文件 sha256 重算的 Merkle 根与 manifest 记载不符")
    if f"root={recomputed}" not in root_txt:
        problems.append("ROOT.txt 未记载重算出的 Merkle 根")
    checks["manifest_root"] = man["merkle"]["root"]

    # 2) ROOT.txt 字节哈希
    rt_sha = hashlib.sha256(root_bytes).hexdigest()
    checks["root_txt_sha256"] = rt_sha
    mf = PKG / "manifest.json"
    if mf.is_file():
        claim = json.loads(mf.read_text(encoding="utf-8")).get("claim", {})
        if claim.get("root_txt_sha256") and claim["root_txt_sha256"] != rt_sha:
            problems.append("ROOT.txt 哈希与 manifest.json claim 不符（包内被替换过？）")
        if claim.get("merkle_root") and claim["merkle_root"] != recomputed:
            problems.append("manifest.json claim 的 merkle_root 与重算不符")

    # 3) RFC3161
    tsr = PKG / "out" / "root.tsr"
    tsa_json = PKG / "out" / "TSA.json"
    if tsr.is_file():
        try:
            for p in (PKG / "tools", PKG):
                sys.path.insert(0, str(p))
            import tsa_verify as V
            from cryptography import x509
            roots = V.public_roots()
            tsa_name = None
            if tsa_json.is_file():
                tsa_name = json.loads(tsa_json.read_text(encoding="utf-8")).get("tsa_name")
            official = None
            fp = PKG / "out" / "tsa_roots" / f"{tsa_name}_cacert.pem"
            alt = PKG / "out" / "tsa_roots" / "cacert.pem"
            for cand in (fp, alt):
                if tsa_name == "freetsa" and cand.is_file():
                    official = x509.load_pem_x509_certificates(cand.read_bytes())[0]
                    break
            vr = V.verify_stamp(tsr, root_bytes, roots, official_root=official)
            checks["rfc3161"] = {k: vr[k] for k in ("status", "gen_time_utc", "imprint_matches_payload",
                                                    "message_digest_ok", "signature_ok", "chain_verified",
                                                    "signer_valid_at_gen_time", "verified")}
            if not vr.get("verified"):
                problems.append("RFC3161 令牌未通过全验（imprint/签名/链/有效期至少一项失败）")
        except Exception as e:
            checks["rfc3161"] = f"未验（{type(e).__name__}: {str(e)[:80]}）"
            problems.append("RFC3161 复验执行失败")
    else:
        checks["rfc3161"] = "包内无令牌"
        problems.append("包内缺 root.tsr")

    # 4) OpenTimestamps 结构一致性（不联网）
    ots = PKG / "out" / "ROOT.txt.ots"
    roots_in_proof = set()
    anchors = json.loads((PKG / "out" / "ANCHORS.json").read_text(encoding="utf-8")) \
        if (PKG / "out" / "ANCHORS.json").is_file() else {}
    if ots.is_file():
        try:
            info = subprocess.run(["ots", "info", str(ots)], capture_output=True, text=True,
                                  encoding="utf-8", timeout=120)
            text = (info.stdout or "") + (info.stderr or "")
            hts = sorted({int(m) for m in re.findall(r"BitcoinBlockHeaderAttestation\((\d+)\)", text)})
            roots_in = {m.lower() for m in re.findall(r"Bitcoin block merkle root ([0-9a-fA-F]{64})", text)}
            roots_in_proof = roots_in
            checks["ots_heights_in_proof"] = hts
            checks["ots_merkle_roots_in_proof"] = len(roots_in)
            rec_hts = anchors.get("heights_in_proof") or []
            if rec_hts and set(rec_hts) != set(hts):
                problems.append("ANCHORS.json 记录的区块高度与 .ots 实际 attestation 不一致")
            for b in anchors.get("blocks", []):
                if b.get("merkle_root") and b["merkle_root"].lower() not in roots_in:
                    problems.append(f"ANCHORS.json 记录的区块 {b.get('height')} merkle root 不在 .ots 内")
        except Exception as e:
            checks["ots"] = f"未验（{type(e).__name__}: {str(e)[:80]}，可无 ots 工具）"
    else:
        checks["ots"] = "包内无 .ots"
        problems.append("包内缺 ROOT.txt.ots")

    # 4b) 包内固化的比特币区块头：离线自校（sha256d == 区块哈希，header 内 merkle root 命中证明）
    hd = PKG / "out" / "btc_headers"
    if hd.is_dir():
        brows, bad = [], 0
        for f in sorted(hd.glob("*.json")):
            r = json.loads(f.read_text(encoding="utf-8"))
            raw = bytes.fromhex(r.get("header_hex", ""))
            sha = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex() if len(raw) == 80 else None
            merkle_from_header = raw[36:68][::-1].hex() if len(raw) == 80 else None
            ok = bool(sha == r.get("block_hash") and merkle_from_header == r.get("merkle_root_from_header")
                      and merkle_from_header in roots_in_proof)
            if not ok:
                bad += 1
                problems.append(f"包内区块头 {r.get('height')}-{r.get('source')} 自校失败")
            brows.append({"height": r.get("height"), "source": r.get("source"),
                          "header_len": len(raw), "sha256d_matches_block_hash": sha == r.get("block_hash"),
                          "merkle_in_proof": merkle_from_header in roots_in_proof, "ok": ok})
        checks["btc_headers"] = {"files": len(brows), "ok": len(brows) - bad, "bad": bad}

    # 5) 日志链 + 日志承诺自洽
    log = PKG / "anchor_log.jsonl"
    chain_f = PKG / "out" / "ANCHOR_LOG_CHAIN.json"
    if log.is_file() and chain_f.is_file():
        raw = log.read_bytes().split(b"\n")
        while raw and not raw[-1].strip():
            raw.pop()
        ch = json.loads(chain_f.read_text(encoding="utf-8"))
        checks["log_lines"] = len(raw)
        head = hashlib.sha256(raw[-1]).hexdigest()
        if ch.get("last_line_sha256") and head != ch["last_line_sha256"]:
            problems.append("anchor_log.jsonl 末行与链头记录不符")
        if ch.get("genesis_sha256") and hashlib.sha256(raw[0]).hexdigest() != ch["genesis_sha256"]:
            problems.append("anchor_log.jsonl 首行与链起点记录不符（历史被改写？）")
        commit = PKG / "out" / "ROOT-LOG.txt"
        la = PKG / "out" / "LOG_ANCHOR.json"
        if commit.is_file():
            text = commit.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"head_sha256=([0-9a-f]{64})", text)
            checks["log_commitment_head"] = m.group(1) if m else None
            if m and m.group(1) != head:
                problems.append("ROOT-LOG.txt 承诺的链头与当前日志末行不符（日志在承诺后新增/被改）")
            if la.is_file():
                laj = json.loads(la.read_text(encoding="utf-8"))
                checks["log_anchor_status"] = laj.get("status")
                if laj.get("anchored_head") and m and laj["anchored_head"] != m.group(1):
                    problems.append("LOG_ANCHOR.json 记录的承诺链头与 ROOT-LOG.txt 不符")
        else:
            checks["log_commitment"] = "包内无 ROOT-LOG.txt（未做日志外锚）"

    # 6) 主张人签名（Ed25519；公钥在包内，独立验签，并核对签名绑定的根 == 重算根）
    claim_f = PKG / "out" / "CLAIM.json"
    sig_f = PKG / "out" / "CLAIM.json.sig"
    pub_f = PKG / "out" / "CLAIMANT_PUBKEY.pem"
    if claim_f.is_file() and sig_f.is_file() and pub_f.is_file():
        try:
            import base64
            from cryptography.hazmat.primitives import serialization
            claim = json.loads(claim_f.read_text(encoding="utf-8"))
            body = json.dumps(claim, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
            pub = serialization.load_pem_public_key(pub_f.read_bytes())
            pub.verify(base64.b64decode(sig_f.read_text(encoding="utf-8").strip()), body)
            fp = hashlib.sha256(pub.public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            checks["claim_signature"] = {"signature_ok": True, "pubkey_fingerprint_sha256": fp,
                                         "claim_id": claim.get("claim_id"),
                                         "bound_merkle_root": (claim.get("subject") or {}).get("merkle_root")}
            if (claim.get("subject") or {}).get("merkle_root") != recomputed:
                problems.append("CLAIM.json 绑定的 merkle_root 与重算根不符")
        except Exception as e:
            checks["claim_signature"] = f"FAILED {type(e).__name__}: {str(e)[:80]}"
            problems.append("主张人签名验不过（CLAIM.json 被改 或 公钥不符）")
    else:
        checks["claim_signature"] = "包内无主张签名文件"

    # 7) 索引台账行级链
    led = PKG / "out" / "INDEX_LEDGER.jsonl"
    if led.is_file():
        rows = [json.loads(l) for l in led.read_text(encoding="utf-8").splitlines() if l.strip()]
        ok = True
        for i, r in enumerate(rows):
            payload = {k: v for k, v in r.items() if k != "entry_hash"}
            want = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()
            if want != r.get("entry_hash"):
                ok = False
            if r.get("prev_entry_hash") != (rows[i - 1]["entry_hash"] if i else None):
                ok = False
        checks["index_ledger"] = {"entries": len(rows), "chain_ok": ok}
        if not ok:
            problems.append("INDEX_LEDGER.jsonl 行级链断裂（某条被改或插入）")

    # 5b) 签名树头（note 格式；签名覆盖空行前文本）
    sth_p = PKG / "out" / "STH.txt"
    if sth_p.is_file():
        try:
            import base64
            from cryptography.hazmat.primitives import serialization
            text = sth_p.read_text(encoding="utf-8")
            body, _, tail = text.partition("\n\n")
            sig_line = [l for l in tail.split("\n") if l.startswith("—")][0]
            sig = base64.b64decode(sig_line.split()[2])
            pub = serialization.load_pem_public_key((PKG / "out" / "CLAIMANT_PUBKEY.pem").read_bytes())
            pub.verify(sig, (body + "\n").encode("utf-8") if not body.endswith("\n") else body.encode("utf-8"))
            checks["sth_signature"] = {"ok": True, "tree_size": body.split("\n")[1],
                                       "note": "Ed25519 note 签名验过"}
        except Exception as e:
            checks["sth_signature"] = f"FAILED {type(e).__name__}: {str(e)[:80]}"
            problems.append("STH 签名验不过（树头被改或公钥不符）")

    out = {"pack": str(PKG), "checks": checks, "problems": problems,
           "verdict": "OK" if not problems else "PROBLEMS"}
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if not problems else 2

if __name__ == "__main__":
    sys.exit(main())
