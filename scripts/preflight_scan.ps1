<#
preflight_scan.ps1 —— 发布前敏感信息预检
用途：提交前扫一遍将要进入仓库的文件，拦住私钥、令牌、绝对路径、主机名、超大文件。
退出码：0 = 干净；1 = 有命中（禁止提交）；2 = 脚本自身出错。

用法（在仓库根目录）：
  pwsh scripts/preflight_scan.ps1
#>

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$hits = New-Object System.Collections.Generic.List[string]
$notes = New-Object System.Collections.Generic.List[string]

$patterns = @(
  @{ name = '私钥头(PEM)';        rx = 'BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY' },
  @{ name = 'GitHub PAT';        rx = 'gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}' },
  @{ name = 'API key(sk-)';      rx = 'sk-[A-Za-z0-9]{20,}' },
  @{ name = 'AWS key';           rx = 'AKIA[0-9A-Z]{16}' },
  @{ name = 'Slack/Stripe 风格';  rx = '(xox[baprs]-|sk_live_[A-Za-z0-9]{10,})' },
  @{ name = 'Windows 绝对路径';   rx = '[A-Za-z]:\\Users\\|[A-Za-z]:\\Workbuddy\\|[A-Za-z]:\\标准\\' },
  @{ name = '本机用户名';         rx = '[A-Za-z]:\\Users\\[^\\"]+' },
  @{ name = '本机主机名';         rx = 'DESKTOP-[A-Z0-9]{4,}|台式机' },
  @{ name = '保险库路径';         rx = 'ucvault_local|\.vault\\' }
)

# 只扫会被提交的内容：git 已跟踪 + 未跟踪但未被忽略的文件
Push-Location $root
try {
  $files = & git ls-files -co --exclude-standard
} finally {
  Pop-Location
}
if (-not $files) { $files = @(Get-ChildItem -Recurse -File $root | ForEach-Object { $_.FullName.Substring($root.Length + 1) }) }

$textExt = @('.md','.json','.jsonl','.txt','.py','.ps1','.js','.html','.yml','.yaml','.ots','.tsr','.pem','.sig','.crl','.der','')

foreach ($f in $files) {
  $path = Join-Path $root $f
  if (-not (Test-Path -LiteralPath $path)) { continue }
  $item = Get-Item -LiteralPath $path
  if ($item.PSIsContainer) { continue }

  # 0) 预检脚本自身含关键词样例（用于拦截同名内容），跳过以免自命中
  if ($f -like '*preflight_scan.ps1') { continue }

  # 1) 超大文件：> 1 MB 必须人工确认
  if ($item.Length -gt 1MB) { $hits.Add("SIZE   $f  $([math]::Round($item.Length/1KB)) KB > 1024 KB") }

  # 2) 二进制白名单：这些只能出现在 attest/ 且必须原名
  $ext = [IO.Path]::GetExtension($path).ToLower()
  if ($ext -in @('.zip','.exe','.dll','.7z','.gz')) { $hits.Add("BINARY $f -> 禁止二进制/压缩包入仓") }

  # 3) 文本内容扫描
  if ($textExt -contains $ext) {
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -eq 0) { continue }
    # .der/.crl/.ots 是二进制但可能含可读串，仍按字节转文本粗扫
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    # 已审计例外：签名产物不得改动（改动即破坏签名），其中若有主机名按"已知例外"放行并记录
    $hostNameExceptions = @('attest/CLAIM.json')
    foreach ($p in $patterns) {
      if ($text -match $p.rx) {
        if ($p.name -eq '本机主机名' -and ($hostNameExceptions -contains ($f -replace '\\','/'))) {
          $notes.Add("KNOWN-EXCEPTION[签名产物原样发布]  $f")
        } else {
          $hits.Add(("PATTERN[{0}]  {1}" -f $p.name, $f))
        }
      }
    }
  }
}

# 4) 只允许公钥类 .pem（主张公钥 + 已公开的第三方日志公钥），禁私钥
$pems = $files | Where-Object { $_ -match '\.pem$' }
foreach ($p in $pems) {
  $ok = ($p -match 'CLAIMANT_PUBKEY\.pem$') -or ($p -match 'REKOR_V2_PUBKEY\.pem$')
  if (-not $ok) { $hits.Add("PEM    $p -> 仅允许公开公钥（CLAIMANT_PUBKEY / REKOR_V2_PUBKEY）") }
  elseif ($p -match 'PRIVATE') { $hits.Add("PEM    私钥文件禁止发布: $p") }
}

# 5) 关键数值与 PUBLICATION.json 对账
$pubFile = Join-Path $root 'PUBLICATION.json'
if (Test-Path -LiteralPath $pubFile) {
  $pub = Get-Content -LiteralPath $pubFile -Raw | ConvertFrom-Json
  $rootTxt = Join-Path $root 'attest\ROOT.txt'
  if (Test-Path -LiteralPath $rootTxt) {
    $h = (Get-FileHash -LiteralPath $rootTxt -Algorithm SHA256).Hash.ToLower()
    if ($h -ne $pub.subject.root_txt_sha256) { $hits.Add("MATCH  attest/ROOT.txt sha256=$h 与 PUBLICATION 记载不一致") }
  }
}

Write-Output ("扫描文件数: {0}" -f @($files).Count)
if ($notes.Count -gt 0) { $notes | Sort-Object -Unique | ForEach-Object { Write-Output "  [note] $_" } }
if ($hits.Count -eq 0) {
  Write-Output 'RESULT: CLEAN（0 命中）'
  exit 0
} else {
  Write-Output 'RESULT: BLOCKED'
  $hits | Sort-Object -Unique | ForEach-Object { Write-Output "  - $_" }
  exit 1
}
