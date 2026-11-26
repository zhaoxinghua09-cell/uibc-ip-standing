# verify_public.ps1 —— 外人一键复验（不依赖本机任何私有材料）
#
# 它做四件事：
#   1. 克隆公开仓（只取公开件）
#   2. 在独立虚拟环境里装 cryptography 并跑 scripts/selfcheck.py（哈希对账 + 验签）
#   3. 拉线上索引页，核对页面根值与仓内根值一致
#   4. 查 Sigstore Rekor 条目，核对 logIndex 与 inclusion proof 规模
#
# 用法：
#   pwsh -File verify_public.ps1                       # 默认克隆到 %TEMP%\ip_public_verify
#   pwsh -File verify_public.ps1 -WorkDir D:\check     # 指定目录
#
# 退出码：0 全通过；1 有项不一致；2 环境/网络问题

param(
    [string]$Repo    = 'https://github.com/zhaoxinghua09-cell/uibc-ip-standing.git',
    [string]$Pages   = 'https://zhaoxinghua09-cell.github.io/uibc-ip-standing',
    [string]$WorkDir = (Join-Path $env:TEMP 'ip_public_verify')
)

$ErrorActionPreference = 'Stop'
$fail = @()
function Say($m) { Write-Output $m }

if (Test-Path $WorkDir) { Remove-Item -LiteralPath $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$clone = Join-Path $WorkDir 'repo'

Say "== 1) clone $Repo"
git clone --quiet $Repo $clone
if ($LASTEXITCODE -ne 0) { Say 'FAIL: 克隆失败（网络或仓不可达）'; exit 2 }
$head = (git -C $clone log --oneline -1)
Say "   HEAD: $head"

Say '== 2) 独立虚拟环境 + selfcheck'
python -m venv (Join-Path $WorkDir 'venv')
$py = Join-Path $WorkDir 'venv\Scripts\python.exe'
& $py -m pip install --quiet --disable-pip-version-check cryptography
& $py (Join-Path $clone 'scripts\selfcheck.py')
if ($LASTEXITCODE -ne 0) { $fail += 'selfcheck 未通过' }

Say '== 3) 线上索引页与仓内数值一致性'
try {
    $idx  = Invoke-RestMethod "$Pages/index.json" -TimeoutSec 30
    $pub  = Get-Content (Join-Path $clone 'PUBLICATION.json') -Raw | ConvertFrom-Json
    $remoteRoot = $idx.commitments.merkle_root
    $localRoot  = $pub.subject.merkle_root
    Say "   remote=$($remoteRoot.Substring(0,16))…  repo=$($localRoot.Substring(0,16))…"
    if ($remoteRoot -ne $localRoot) { $fail += '线上页面根值与仓内 PUBLICATION 不一致' }
} catch { $fail += "索引页不可达：$($_.Exception.Message)" }

Say '== 4) Rekor 条目'
try {
    $proof = Get-Content (Join-Path $clone 'attest\REKOR_PROOF.json') -Raw | ConvertFrom-Json
    $ent = Invoke-RestMethod "https://rekor.sigstore.dev/api/v1/log/entries/$($proof.uuid)" -TimeoutSec 60
    $e = $ent.PSObject.Properties.Value[0]
    $hashes = @($e.verification.inclusionProof.hashes).Count
    Say "   logIndex=$($e.logIndex)  integratedTime=$($e.integratedTime)  proof_hashes=$hashes  treeSize=$($e.verification.inclusionProof.treeSize)"
    if ($e.logIndex -ne $proof.logIndex) { $fail += 'Rekor logIndex 与本地记录不一致' }
    if ($hashes -lt 1) { $fail += 'Rekor 条目缺 inclusion proof' }
} catch { $fail += "Rekor 条目不可查：$($_.Exception.Message)" }

Say '== 5) 仓内敏感信息抽查（应全部为 0）'
$hits = Select-String -Path (Join-Path $clone '*'), (Join-Path $clone 'attest\*'), (Join-Path $clone 'scripts\*') `
        -Pattern 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY', 'gh[pousr]_[A-Za-z0-9]{20,}', 'sk-[A-Za-z0-9]{20,}' `
        -ErrorAction SilentlyContinue
Say "   命中=$(@($hits).Count)"
if (@($hits).Count -gt 0) { $fail += '仓内疑似含私钥或令牌' }

Say ''
if ($fail.Count -eq 0) { Say 'RESULT: PASS（四项独立核对全部一致）'; exit 0 }
Say 'RESULT: FAIL'
$fail | ForEach-Object { Say "  - $_" }
exit 1
