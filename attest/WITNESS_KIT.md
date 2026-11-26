# 第三方见证包（Witness Kit）

请求编号：`WITNESSREQ-20261126-134839`　生成时间：2026-11-26T13:48:39+0800

## 要见证什么（逐项独立复算）

| # | 项目 | 值 | 怎么核 |
|---|---|---|---|
| 1 | 文件集合 Merkle 根 | `bd08d9b237d16aebc1f3fc03c738168e398814407d20e07abda3388cec17773a` | 用包内 MANIFEST.json 逐文件 sha256 重算（verify_offline.py 第 1 项） |
| 2 | ROOT.txt sha256 | `dda8ccf18d4f1cf1eb62a804fc1e7d1cfcb884f37283d6ead4e0260072992e72` | sha256(out/ROOT.txt) |
| 3 | 比特币区块高度 | `977354…, 977367…, 977390…` | 到 blockstream.info / mempool.space 查该高度，核对区块哈希与 merkle root |
| 4 | 比特币区块哈希 | `00000000000000000000…, 00000000000000000001…, 00000000000000000000…` | 同上；并核对 header 内 merkle root 与 .ots 证明内记录的根一致 |
| 5 | RFC3161 genTime | `2026-11-26T04:50:28+00:00` | sha512(ROOT.txt) 应与令牌 imprint 一致；签名与链用 verify_pack.py 验 |
| 6 | 主张公钥指纹 | `866dab20c9ebb067ef38db75ee3f684c275b1fcce21984355ba77decb6a0468e` | sha256(CLAIMANT_PUBKEY.pem 的 SubjectPublicKeyInfo-DER) |
| 7 | 主张签名字节 sha256 | `3b7ee668cc1ec67108ddc5f2a494fbecd205673342d40b90cd4b79f903a83148` | sha256(out/CLAIM.json.sig) |
| 8 | 日志外锚链头 | `410d0894f8e505b24fee31b6eea62fd3f3eb36c498f7ca3879a9e8e74e0a91e0` | 核对 out/ROOT-LOG.txt 内 head_sha256= 与 anchor_log.jsonl 末行 sha256 |
| 9 | 索引台账链头 | `579dde77889048c9a5d3afd21953c23e3ce8ee853024e117c859c851517e114e` | 核对 out/INDEX_LEDGER.jsonl 末条的 entry_hash |

## 见证人怎么做（10 分钟）

- 1. 解压 zip，进目录
- 2. python verify_offline.py .（零依赖；应输出 grade=VERIFIED_STRUCTURE、problems=[]）
- 3. python verify_pack.py .（若已装 cryptography，应输出 verdict=OK、problems=[]）
- 4. 对 items 逐项独立复算，记录每个值与包内记载是否一致
- 5. 填 WITNESS_RECEIPT_TEMPLATE.json 并用你自己的密钥/机构印章签名，回传

## 见证意味着什么 / 不意味着什么

- 意味着：见证人独立核算下列数值，确认与包内文件一致，并用自己的身份/签名出具回执。见证不转移权属，只增加一个独立第三方对'当时这些哈希就是这些值'的旁证。
- 不意味着：见证人不保证内容合法、不保证未来不变、也不为权属背书；只看哈希是否一致。

## 回执

填 `WITNESS_RECEIPT_TEMPLATE.json`，回传后由己方登记进 `WITNESS_LEDGER.jsonl`。
