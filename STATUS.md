# 现状总账（收尾版）

生成日：2026-11-26（本页随每次发布重写，数值以 `index.json` / `attest/*.json` 为准）

## 一、被承诺的对象

| 项 | 值 |
|---|---|
| 文件数 | 2683 |
| Merkle 根 | `bd08d9b237d16aebc1f3fc03c738168e398814407d20e07abda3388cec17773a` |
| 树深 | 12 |
| `ROOT.txt` sha256 | `dda8ccf18d4f1cf1eb62a804fc1e7d1cfcb884f37283d6ead4e0260072992e72` |
| pack_id | `20261126-dda8ccf18d4f` |

## 二、锚（七条独立轨）

| 轨 | 现状 | 可核方式 |
|---|---|---|
| 比特币（3 区块） | 977354 / 977367 / 977390，blockstream+mempool 双源一致 | 公共浏览器 |
| RFC3161 | **6 家 TSA 取证、6 家验签通过、4 家链到公共根**（DigiCert / Certum / Sectigo→USERTrust RSA / GlobalSign R6） | `attest/TSA.json` |
| 主张签名 | Ed25519，指纹 `866dab20…0468e` | 公钥在仓 |
| 日志链头（只增） | 11 行，`head_sha256=9abd56ef…d0f8` | 重算哈希链 |
| 索引台账 / STH | 1 条，`head=579dde77…114e` | 重算 |
| Sigstore Rekor v1 | `logIndex=4121954662`，2026-11-26T08:23:07Z | 官方 API 直查 |
| Sigstore Rekor v2 | `logIndex=217674183`，18 hash 入证，checkpoint 由 4 家外部 witness 联签 | 本地自算 + checkpoint 防回滚 |

## 三、身份与入口

| 项 | 现状 |
|---|---|
| did:web | `did:web:zhaoxinghua09-cell.github.io:uibc-ip-standing`（`did.json`，公钥逐字节对账） |
| 零安装复验页 | `verify.html`（8 项，浏览器内完成） |
| 一条命令复验 | `./verify.sh` / `python3 scripts/verify_min.py`（10 项，标准库；`--json` 出裁定） |
| 别人的 CI | `verify-external.yml`（workflow_call，未真实被第三方调用） |
| 证书 | `certificate.html`（A4，可打印/存 PDF） |
| 连续性 | `continuity.html`，每日心跳 + 哈希链，停更 3 天 CI 报红 |
| 见证 | `witness.html` + Issue 表单 + 五步机器初核；**回执 0 条** |

## 四、守门（CI 17 步）

敏感词预检 → selfcheck（哈希/签名/三方一致）→ 规范字节一致 → 证书数值 → 见证模板不得过期 → v2 自算 → v2 checkpoint 联签 ≥2 → verify.html 无头实跑 → 连续性守门 → 零依赖复验 → fail-closed 自测（5 篡改全抓）→ DID 绑定 → JSON 回执结构。任一红即拦。

## 五、诚实缺口（不掩饰）

1. **法律推定**：没有 eIDAS 合格 TSP / 公证，所有锚只证明"存在与时间"，不产生法律效力。
2. **真人见证回执 = 0**：机制就绪，差人签字。
3. **在线 API / SLA**：静态托管，做不了鉴权、配额、可用性承诺。
4. **连续性只有 1 天**：机制有了，天数得靠时间攒。
5. **v2 条目不能在线重取**：公开实例 tile 路径 404，只能本地 body+proof 自算。
6. **继任密钥未生成**：程序写明，无真实需求不造。
7. **可复用工作流未经真实第三方调用**。

## 六、一条命令自查

```bash
git clone https://github.com/zhaoxinghua09-cell/uibc-ip-standing && cd uibc-ip-standing && ./verify.sh
```

## 七、独立机器实测记录

| 机器 | 角色 | 结果 |
|---|---|---|
| 家用台式机（写者） | 生成、签名、发布 | `verify_min.py` 10 项 PASS |
| 云主机（Linux，干净环境，无私钥、无历史文件） | 纯第三方视角 | `git clone --depth 1` → `python3 scripts/verify_min.py` → **PASS（10 项，0 失败）**，含 DID 在线解析、Rekor 在册 |
| 公司机（只读机） | 只读核验 | Pages / `ROOT.txt` sha256 / Rekor logIndex 三项通过；该机 `github.com:443` 不通，无法 clone |

线上可用性备注：GitHub Pages 会偶发 503（本次实测 `did.json` 首请求 503、5 秒后重试 3 次均 200）。静态托管没有 SLA，抓取方应带重试；这不是文件问题。
