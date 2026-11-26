# 公开范围（发布红线）

本仓库按"**只公开承诺、不公开内容**"设计。下面是逐项的收录与排除决定，以及理由。

## 一、收录（可以公开，且公开有实际作用）

| 文件 | 作用 |
|---|---|
| `attest/ROOT.txt` | Merkle 根的文本载体，公开它等于公开"承诺的对象标识" |
| `attest/ROOT.txt.ots` | 比特币锚证明，任何人可用区块头复核 |
| `attest/ROOT-LOG.txt(.ots)` | 日志链头承诺 |
| `attest/INDEX-LEDGER.txt(.ots)`、`INDEX_LEDGER.jsonl` | 只增台账内容（仅哈希与元数据，无路径）与链头承诺 |
| `attest/STH.json`、`STH-*.txt.ots` | 签名树头及树头自身的锚 |
| `attest/ANCHORS.json` | 三个区块高度/哈希/时间与双源比对结论 |
| `attest/TSA.json`、`TSA_GUARD.json`、`TSA_PIN_BASELINE.json` | 令牌验签结果、TSA 冗余与守卫阈值、钉扎基线 |
| `attest/CLAIM.json`、`CLAIM.json.sig`、`CLAIMANT_PUBKEY.pem`、`CLAIMANT_FINGERPRINT.txt` | 主张文本与可独立验证的公钥/指纹 |
| `attest/CLAIM_VERIFY.json`、`CLAIM_ANCHOR.json`、`IP_VERIFY.json` | 验签与绑定结果 |
| `attest/HEALTH.md`、`RECHECK_SCHEDULE.json` | 健康看板与证书吊销重查日程 |
| `attest/WITNESS_*` | 见证工具包与回执模板（公开后任何人都能照做见证） |
| `docs/`、`verify/`、`index.*` | 报告、复验器、公开索引页 |

## 二、排除（不得公开）

| 排除项 | 理由 |
|---|---|
| `ip/.vault/`（Ed25519 私钥） | 公开即放弃抗抵赖；泄露后签名方可主张"他人代签" |
| 2683 个被承诺的原始文件 | 商业内容与项目文稿本体，公开即泄密；只公开其哈希承诺 |
| `MANIFEST.json`、`files_claim.json`、`SHA256SUMS.txt` | 含 2683 条文件**路径**，路径名本身可能泄露项目内容与结构 |
| `IP_EVIDENCE_PACK_*.zip` 整包 | 内含上述清单文件，等同间接触发路径泄露；需要时由主张人按需分发 |
| `tsa_tokens/*.tsr` 原始令牌 | 可公开但非必需；随证据包分发，仓库只放验签结论与 imprint |
| `EXTERNAL_AI_REVIEW*.json` | 红队审稿记录，含对外部服务的调用细节，属内部质量材料 |
| 任何本机绝对路径、主机名、账号名 | 已对报告做脱敏；预检脚本会拦住回潮 |
| 凭据（PAT / API key） | 永不进仓；预检脚本硬拦 |

## 二·补 已审计例外

| 文件 | 例外内容 | 为什么放行 |
|---|---|---|
| `attest/CLAIM.json` | 主张文本中提及"当前会话执行主机"名称 | 该文件是**已签名产物**，改动一个字节即破坏 Ed25519 签名与后续上链承诺；只能原样发布。主机名本身不含账号、口令或文件内容，且已在 `PUBLICATION.json` 与本预检脚本里登记为例外，新增同类命中仍会阻断 |

## 三、发布前必做

1. `pwsh scripts/preflight_scan.ps1` —— 扫私钥头、令牌前缀、绝对路径、主机名、超大文件；有命中则退出非 0，禁止提交。
2. 逐项核对 `PUBLICATION.json` 的数值与 `attest/` 内文件一致（脚本会打印比对结果）。
3. 人工过一次 `git status` 与 `git diff --stat`，确认没有意外新增。

## 四、这条边界要写清

公开承诺极大地提升了"事后抵赖"的成本，但它并不把本仓库变成公证处：没有人替我们保管证据、也没有第三方出具见证回执。任何人若在本仓库数值与证据包数值之间发现不一致，应当**直接判定证据失效并追问**，而不是折中处理。
