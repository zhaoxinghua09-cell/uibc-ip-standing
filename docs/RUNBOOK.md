# RUNBOOK · 第一次来的人怎么验（5 分钟）

三种人，三条路，各自 5 分钟内能出结论。**不需要账号、不需要付费、不需要懂哈希。**

---

## 路径 A：只用浏览器（最快，约 30 秒）

1. 打开 <https://zhaoxinghua09-cell.github.io/uibc-ip-standing/verify.html>
2. 点「重新复验」，等 5–15 秒
3. 结果是逐项 PASS/FAIL

**怎么读**：全绿 = 公开数值彼此自洽、签名有效、Rekor 日志条目在册；出现 FAIL = 本站展示的数值被改动，或你的下载不完整。

> 不需要 WebCrypto Ed25519 的老浏览器会退化成"跳过验签"，页面会明确标注，不会假装通过。

---

## 路径 B：要一份文件自己跑（约 2 分钟）

**没有 git 也能做**（这是最容易卡住的地方）：

```powershell
# 1) 下载 zip（约 173 KB）
curl.exe -L -o repo.zip https://codeload.github.com/zhaoxinghua09-cell/uibc-ip-standing/zip/refs/heads/main
# 2) 解压
Expand-Archive repo.zip -DestinationPath .
cd uibc-ip-standing-main
# 3) 跑
python scripts\verify_min.py          # 期望：PASS（10 项，0 失败）
python scripts\selftest_negative.py   # 期望：FAIL_CLOSED_OK（5/5 被抓）
```

有 git 就用 `git clone https://github.com/zhaoxinghua09-cell/uibc-ip-standing`，其余一样。

**实测记录（2026-11-26，Windows 11 + Python 3.13，干净目录、无 `.git`）**：zip 177,250 B → `verify_min.py` PASS 10/10、`selftest_negative.py` FAIL_CLOSED_OK 5/5。

---

## 路径 C：想当见证人（约 3 分钟）

<https://zhaoxinghua09-cell.github.io/uibc-ip-standing/witness.html>

三步：点一下按钮 → 截图或贴结论 → 开 Issue 交回执。回执只登记"你在某时看到这些数值彼此自洽"，不登记你的私人信息（除非你自己写）。

---

## 路径 D：给机器看（CI / 监控用）

```bash
curl -s https://zhaoxinghua09-cell.github.io/uibc-ip-standing/attest/VERIFY_RECEIPT.json | head -40
```

这份 JSON 有 `schema` / `verdict` / 逐项 `checks` / 计数 / 边界声明，可以直接和上次的结果 diff——比解析网页或 PDF 稳。

---

## 故障排除（都是我们真踩过的）

| 现象 | 原因 | 怎么办 |
|---|---|---|
| `python: command not found` | 只装了 python3 | 把 `python` 换成 `python3` |
| 没有 git / clone 卡住 | 环境限制 | 走路径 B 的 zip，不需要 git |
| 跑 `.ps1` 报 `Missing closing '}'` | 用 Windows PowerShell 5.1 读 UTF-8 脚本 | 换 `pwsh`（PowerShell 7）跑 |
| `did.json` 第一次 503 | 静态托管的偶发问题 | 重试一次即 200，不是数据坏了 |
| 断网时 DID / Rekor 两项 WARN | 那两项要联网 | WARN 不算失败，核心哈希项离线可算 |
| 哈希一项对不上 | 真的被改了，或下载不完整 | 先重下；仍对不上请开 Issue 并附你的输出 |

---

## 本页不保证什么

- 不保证内容权属，不构成公证或法律意见；
- 原始 2683 个文件不公开，你无法从本仓还原文件内容；
- 见证回执目前为 0 条——"有人独立看过"这件事还没有发生过，这正是本仓要求的下一步。
