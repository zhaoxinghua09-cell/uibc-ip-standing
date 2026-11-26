# uibc-ip-standing —— IP 权属证据链的公开承诺件

本仓库只做一件事：把一套私有证据链的**承诺数值**（哈希、比特币区块、RFC3161 时间戳、签名）公开陈列，使任何人都能独立核对、并对未来的任何改动形成对账压力。

它**不是**公证，**不是**权属背书，**不**托管原始证据文件。边界写在 [`PUBLISH_SCOPE.md`](PUBLISH_SCOPE.md)。

**公开索引页（已上线）**：<https://zhaoxinghua09-cell.github.io/uibc-ip-standing/> —— 无需登录、无需装任何工具，打开即可看到当前承诺数值；页面源码与 `index.json` 同在本仓库，可自行比对。

---

## 一、被承诺的对象

| 项目 | 值 |
|---|---|
| 文件数 | 2683 |
| 集合 Merkle 根 | `bd08d9b237d16aebc1f3fc03c738168e398814407d20e07abda3388cec17773a` |
| 树深 | 12 |
| `ROOT.txt` sha256 | `dda8ccf18d4f1cf1eb62a804fc1e7d1cfcb884f37283d6ead4e0260072992e72` |

根由逐文件 sha256 两两上推得出，`ROOT.txt` 是其文本载体。**原始文件本身不在此仓库**，仅凭这里的数据无法还原文件内容，也无法判断内容是什么——这正是设计意图：证明"存在与时刻"，不泄露内容。

## 二、五个独立锚（含一个公共透明日志条目）

| 锚 | 明细 | 独立复核方式 |
|---|---|---|
| 比特币区块（OpenTimestamps） | 977354 / 977367 / 977390，双源（blockstream.info + mempool.space）区块头比对一致 | 按高度查区块，核对区块哈希与 merkle root |
| RFC3161 时间戳 | DigiCert，genTime `2026-11-26T12:50:28+08:00`（= 04:50:28Z），sha512 `196b77c1…738d` 即 `sha512(ROOT.txt)` | `sha512sum ROOT.txt` 比对令牌 imprint；或直接看 `attest/TSA.json` 的验签字段 |
| 主张签名 | Ed25519，公钥指纹 `866dab20c9ebb067ef38db75ee3f684c275b1fcce21984355ba77decb6a0468e`，签名已再上链 | 用 `attest/CLAIMANT_PUBKEY.pem` 验 `attest/CLAIM.json` + `.sig` |
| **Sigstore Rekor 公共透明日志** | `logIndex=4121954662`，`integratedTime=1795681387` → **2026-11-26T08:23:07Z**；入证证明 27 个 hash、`treeSize=4000053123`；条目 UUID `108e9186…50192f4c9ebb5150b3bb` | 直接查 `https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677a55a93624154410a2e0ac514c94f8356c6fbb1f246f1201922f4c9ebb5150b3bb`；本地副本 [`attest/REKOR_PROOF.json`](attest/REKOR_PROOF.json) |
| 日志外锚链头 | `9abd56effd3c0d3da394a7467d666d58742aac76a313b2a97263dc0001f7d0f8`（11 行日志），OTS 已提交待进块 | 核对 `attest/ROOT-LOG.txt` 内 `head_sha256=` |

三处区块的具体哈希与时间见 [`attest/ANCHORS.json`](attest/ANCHORS.json)；完整验签明细见 [`attest/TSA.json`](attest/TSA.json)。外部存在守恒检查（仓/CI/Pages/Rekor 四处每日对账）见 [`attest/REPO_WATCH.json`](attest/REPO_WATCH.json)。

## 三、自己核（不需要我们的工具）

1. **核 ROOT.txt**：`sha256sum attest/ROOT.txt` → 应为 `dda8ccf1…992e72`（与 `index.json` 一致）。
2. **核区块**：任取 977354 / 977367 / 977390，到 blockstream.info 与 mempool.space 查两次，比对区块哈希与 merkle root；两源一致才算锚定成立。
3. **核签名**：签名覆盖的是 `CLAIM.json` 的**规范字节**（`sort_keys=True, separators=(",", ":"), ensure_ascii=False` 的 UTF-8 序列化），不是原文件字节——原文件带缩进，直接对它验签会失败。用公钥验：

```python
import json, base64
from cryptography.hazmat.primitives import serialization
pk = serialization.load_pem_public_key(open("attest/CLAIMANT_PUBKEY.pem","rb").read())
body = json.dumps(json.load(open("attest/CLAIM.json",encoding="utf-8")),
                  ensure_ascii=False, sort_keys=True, separators=(",",":")).encode("utf-8")
pk.verify(base64.b64decode(open("attest/CLAIM.json.sig").read().strip()), body)
print("signature OK")
```

规范字节的 sha256 应为 `e1d07c4dcaff10cabcf37022035a555ed56af294e649c0424c0ca62bf9f3ebb8`；公钥指纹应为 `866dab20…0468e`（对 SPKI-DER 求 sha256）。
4. **核令牌**：`openssl ts -verify -in <令牌> -data attest/ROOT.txt -CAfile <DigiCert Trusted Root G4>`（令牌随证据包按需提供，本仓库只放验签结果与 imprint）。
5. **核内部一致性**：`python verify/verify_offline.py <证据包解压目录>` —— 纯标准库，校验清单→Merkle、ROOT.txt、区块头 `sha256d`、台账链、日志链、签名绑定。

`verify/verify_offline.py` 只依赖 Python 标准库；`verify/verify_pack.py` 需要 `cryptography` 与 `ots`。两者都会把"因缺库而跳过的项"显式列为 degraded，不会假装通过。

## 四、为什么这些数值不易被伪造

- 区块哈希无法凭空构造，修改一个字节就会破坏整条链到区块头的路径；
- 三个不同高度的区块 + 四家 TSA（其中两家链到公共根）+ 自持密钥签名，任一轨被攻破，其余轨仍可支撑；
- 台账只增、链头与树头公开：**改旧行必被发现**（但"瞒着不写"与"分叉"本地无法自证，见边界）。

## 五、明确不主张（先看这里）

1. 不构成公证、鉴定或法律意见；不替代登记与合同。
2. 不保证内容合法、不保证第三方权利、不为任何产品背书。
3. 抗抵赖以私钥未泄露为前提（Ed25519 固有边界）；私钥泄露即可被主张"他人代签"。
4. 台账防改不防瞒、不防分叉；只能靠链头公开对账发现分歧。
5. 时间锚成立的前提是"该区块哈希确实存在于比特币主链"——这需要你自行查区块浏览器，本仓库不代你判断。
6. 本仓库无托管方、无第三方见证回执（`attest/WITNESS_LEDGER.jsonl` 未公开，回执数为 0）。

## 六、仓库结构

```
index.html / index.json      公开索引页（单文件静态页，可自行部署）
attest/                      承诺件：ROOT.txt、各锚证明、令牌验签结果、主张与签名、看板、见证工具包
docs/                        对标与实测报告（已脱敏本机路径）
verify/                      两个复验器（零依赖版 / 完整版）
scripts/preflight_scan.ps1   发布前敏感信息预检（提交前必跑）
PUBLICATION.json             本条发布的承诺数值快照（机器可读）
PUBLISH_SCOPE.md             公开范围与排除项、以及为什么排除
```

## 七、发布记录

每次发布在 `git log` 与 `PUBLICATION.json` 中留痕。任何两份副本若在相同 `publication_id` 下数值不一致，即应判为分叉或替换，直接认定证据失效。

## 八、许可

文档：CC BY 4.0；代码：MIT；承诺件（哈希、令牌、签名、证明）为事实性数据，可自由引用与核对，但**不得改动后重新发布**。

---

### English summary

A public commitment record for a private IP evidence chain: 2,683 files → Merkle root `bd08d9b2…7773a` → `ROOT.txt` → Bitcoin blocks 977354/977367/977390 (OpenTimestamps, dual-source verified) + a DigiCert RFC3161 timestamp (genTime 2026-11-26T04:50:28Z) + an Ed25519 authorship claim (fingerprint `866dab20…0468e`). Only commitments are published; source files, private keys and file listings are not. This is **not** a notarization and makes **no** ownership endorsement. Verification requires no trust in us: recompute the hashes, check the blocks on a public explorer, verify the signature with the published public key.
