<#
 geohide-probe.ps1 - проверка прокси GeoHide с ПК пользователя (с его провайдера).
 Раннер GitHub в США не видит блокировок РКН, поэтому живость адресов проверяется здесь.

 Что делает:
  1. Берёт "ядро" EU-адресов GeoHide (IP, которые стоят почти у каждого домена EU-hosts).
  2. Для каждого проверяет TLS до claude.ai, chatgpt.com и platform.claude.com (curl --resolve).
  3. Выбирает MAIN (самый быстрый живой) и ALT (второй), а для Gemini ищет адрес без /sorry.
     Статус Gemini пишется комментарием в health.txt: clean / ai-only / dead.
  4. Если MAIN/ALT/GEMINI отличаются от health.txt в форке, коммитит новый health.txt через
     GitHub API. Коммит запускает пересборку hosts-ai.txt, а сразу после коммита скрипт
     отправляет repository_dispatch в DnsConf, чтобы NextDNS обновился без ожидания крона.
  5. Если живых адресов нет совсем или Gemini деградирован, показывает уведомление в трее
     (не чаще раза в 6 часов на событие).

 Пропускает проверку, если включён VPN-адаптер или запущен zapret (winws): результат был бы ложным.
 Токен: fine-grained, репозитории ISa1m0n/GeoHideDNS и ISa1m0n/DnsConf, право Contents: Read and write.
 Лежит рядом со скриптом в файле geohide-probe.token (одна строка).

 Параметры: -DryRun (ничего не коммитить), -Force (не пропускать при VPN/zapret), -NoNotify (без уведомлений),
 -ForceCommit (записать health.txt даже без изменения адресов, для проверки цепочки).
#>
param([switch]$DryRun, [switch]$Force, [switch]$NoNotify, [switch]$ForceCommit)

$Repo         = 'ISa1m0n/GeoHideDNS'
$DispatchRepo = 'ISa1m0n/DnsConf'
$Branch       = 'main'
$TokenFile    = Join-Path $PSScriptRoot 'geohide-probe.token'
$LogFile      = Join-Path $PSScriptRoot 'geohide-probe.log'
$StateFile    = Join-Path $PSScriptRoot 'geohide-probe.state'
$HealthFile   = Join-Path (Split-Path $PSScriptRoot -Parent) 'health.txt'
$EuHosts      = 'https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/eu/hosts'
$TestDomains  = 'claude.ai', 'chatgpt.com', 'platform.claude.com'
# DoH-сервисы: у кого-то из них может появиться чистый адрес Gemini.
# Список можно дополнять; недоступные серверы просто пропускаются.
$DohServers   = @(
  'https://dns.dagami.ru/dns-query',
  'https://dns.zapret.moe/dns-query',
  'https://dns.bezmezhau.com/dns-query'
)
$DohTimeout   = 4
$NotifyEvery  = 6 * 3600     # не чаще раза в 6 часов на одно и то же событие
$Api          = "https://api.github.com/repos/$Repo/contents/health.txt"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Log($msg) {
  $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $msg
  Write-Host $line
  try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch {}
  # не даём логу расти бесконечно
  try { if ((Get-Item $LogFile).Length -gt 512KB) { $keep = Get-Content $LogFile -Tail 400; Set-Content -Path $LogFile -Value $keep -Encoding UTF8 } } catch {}
}

# Уведомление в трей. Ничего не устанавливаем, обходимся WinForms.
# Одно и то же событие показываем не чаще раза в $NotifyEvery секунд.
function Alert([string]$key, [string]$title, [string]$text) {
  if ($NoNotify) { return }
  $state = @{}
  try {
    if (Test-Path $StateFile) {
      foreach ($l in (Get-Content $StateFile)) {
        if ($l -match '^(\S+)\s+(\d+)$') { $state[$Matches[1]] = [long]$Matches[2] }
      }
    }
  } catch {}
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  if ($state.ContainsKey($key) -and ($now - $state[$key]) -lt $NotifyEvery) { return }
  $state[$key] = $now
  try {
    ($state.Keys | ForEach-Object { "$_ $($state[$_])" }) | Set-Content -Path $StateFile -Encoding UTF8
  } catch {}
  try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $ni = New-Object System.Windows.Forms.NotifyIcon
    $ni.Icon = [System.Drawing.SystemIcons]::Warning
    $ni.BalloonTipTitle = $title
    $ni.BalloonTipText = $text
    $ni.Visible = $true
    $ni.ShowBalloonTip(10000)
    Start-Sleep -Seconds 6
    $ni.Dispose()
  } catch {}
  Log "Уведомление: $title - $text"
}

# --- защита от ложных результатов ---
if (-not $Force) {
  $vpn = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription + ' ' + $_.Name) -match 'Wintun|TAP-Windows|Happ|sing-box|WireGuard|OpenVPN' }
  if ($vpn) { Log "Пропуск: активен VPN-адаптер ($($vpn[0].Name))"; exit 0 }
  if (Get-Process -Name winws -ErrorAction SilentlyContinue) { Log 'Пропуск: запущен zapret (winws)'; exit 0 }
}

# --- токен ---
if (-not (Test-Path $TokenFile)) { Log "Нет файла токена: $TokenFile"; exit 1 }
$Token = (Get-Content $TokenFile -Raw).Trim()
$Headers = @{ Authorization = "Bearer $Token"; Accept = 'application/vnd.github+json'; 'User-Agent' = 'geohide-probe'; 'X-GitHub-Api-Version' = '2022-11-28' }

# --- текущее состояние health.txt в форке ---
$cur = @{ MAIN = ''; ALT = ''; GEMINI = '' }
$sha = $null
try {
  $r = Invoke-RestMethod -Uri "${Api}?ref=$Branch" -Headers $Headers -ErrorAction Stop
  $sha = $r.sha
  $txt = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($r.content -replace '\s', '')))
  foreach ($l in ($txt -split "`n")) {
    if ($l -match '^(MAIN|ALT|GEMINI)\s+(\S+)') { $cur[$Matches[1]] = $Matches[2] }
  }
} catch {
  if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { Log 'health.txt в форке ещё нет, беру defaults.txt' }
  else { Log "Не удалось прочитать health.txt: $($_.Exception.Message)"; exit 1 }
}

if (-not $cur.MAIN) {
  $def = (& curl.exe -s -m 20 "https://raw.githubusercontent.com/$Repo/$Branch/defaults.txt") -split "`n"
  foreach ($l in $def) { if ($l -match '^(MAIN|ALT|GEMINI)\s+(\S+)') { $cur[$Matches[1]] = $Matches[2] } }
  Log "Старт от defaults.txt: MAIN=$($cur.MAIN) ALT=$($cur.ALT) GEMINI=$($cur.GEMINI)"
}

# --- ядро EU-адресов ---
$counts = @{}
$eu = (& curl.exe -s -m 30 $EuHosts) -split "`n"
foreach ($l in $eu) {
  if ($l -match '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\S') { $counts[$Matches[1]] = 1 + [int]$counts[$Matches[1]] }
}
$core = @($counts.Keys | Where-Object { $counts[$_] -ge 500 })
if ($core.Count -eq 0) { Log 'Не удалось получить список EU-адресов (raw.githubusercontent.com недоступен?)'; exit 1 }

# --- проверка одного адреса: среднее время TLS (мс) по всем доменам или $null ---
function Test-Proxy([string]$ip) {
  $sum = 0.0
  foreach ($d in $TestDomains) {
    $best = $null
    foreach ($try in 1..2) {
      $out = & curl.exe -s --connect-timeout 4 -m 8 -o NUL -w '%{http_code} %{time_appconnect}' --resolve "${d}:443:$ip" "https://$d" 2>$null
      $p = ("$out").Trim() -split ' '
      if ($p.Count -eq 2 -and $p[0] -ne '000' -and [double]$p[1] -gt 0) {
        $t = [double]$p[1]
        if ($null -eq $best -or $t -lt $best) { $best = $t }
      }
    }
    if ($null -eq $best) { return $null }
    $sum += $best
  }
  return [int]($sum * 1000 / $TestDomains.Count)
}

# --- Gemini: Ok = веб-чат без /sorry и AI Studio живой; Ai = живой хотя бы AI Studio ---
function Test-Gemini([string]$ip) {
  $g = ("" + (& curl.exe -s --connect-timeout 4 -m 12 -o NUL -w '%{http_code} %{redirect_url}' --resolve "gemini.google.com:443:$ip" 'https://gemini.google.com/' 2>$null)).Trim()
  $a = ("" + (& curl.exe -s --connect-timeout 4 -m 12 -o NUL -w '%{http_code} %{redirect_url}' --resolve "aistudio.google.com:443:$ip" 'https://aistudio.google.com/' 2>$null)).Trim()
  $gOk = ($g -match '^(200|301|302)') -and ($g -notmatch 'sorry')
  $aOk = ($a -match '^(200|301|302)') -and ($a -notmatch 'sorry')
  $gs = ($g -replace '\?.*$', '')
  $as = ($a -replace '\?.*$', '')
  return @{ Ok = ($gOk -and $aOk); Ai = $aOk; Info = "gemini: $gs | aistudio: $as" }
}

# --- 1. MAIN / ALT ---
$scores = @{}
foreach ($ip in $core) {
  $s = Test-Proxy $ip
  if ($null -ne $s) { $scores[$ip] = $s }
}
$ranked = @($scores.Keys | Sort-Object { $scores[$_] })
Log ("EU-адреса: " + (($core | ForEach-Object { if ($scores.ContainsKey($_)) { "$_=$($scores[$_])мс" } else { "$_=мертв" } }) -join '  '))
if ($ranked.Count -eq 0) {
  Log 'Ни один EU-адрес не отвечает, health.txt не трогаю'
  Alert 'main-dead' 'GeoHide: живых адресов нет' 'Ни один EU-адрес не прошёл проверку TLS. Проверь провайдера, zapret и апстрим GeoHide.'
  exit 2
}

$main = $ranked[0]
# не прыгаем между адресами без нужды: текущий MAIN остаётся, пока жив и не сильно медленнее лучшего
if ($cur.MAIN -and $scores.ContainsKey($cur.MAIN) -and $scores[$cur.MAIN] -le ($scores[$main] * 1.5 + 60)) { $main = $cur.MAIN }
$alt = $null
if ($cur.ALT -and $cur.ALT -ne $main -and $scores.ContainsKey($cur.ALT)) { $alt = $cur.ALT }
if (-not $alt) { $alt = $ranked | Where-Object { $_ -ne $main } | Select-Object -First 1 }
if (-not $alt) { $alt = $main }

# --- 2. GEMINI ---
$cand = New-Object System.Collections.Generic.List[string]
if ($cur.GEMINI) { $cand.Add($cur.GEMINI) }
foreach ($d in $DohServers) {
  $ip = & curl.exe -s --connect-timeout 3 -m $DohTimeout --doh-url $d -o NUL -w '%{remote_ip}' 'https://gemini.google.com/' 2>$null
  $ip = "$ip".Trim()
  if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
    Log "  DoH $d -> $ip"
    if (-not $cand.Contains($ip)) { $cand.Add($ip) }
  }
}
foreach ($ip in $ranked) { if (-not $cand.Contains($ip)) { $cand.Add($ip) } }
$gemini = $null
$aiOnly = $null
foreach ($ip in $cand) {
  $t = Test-Gemini $ip
  Log "  Gemini $ip : $($t.Info)"
  if ($t.Ok) { $gemini = $ip; break }
  if ($t.Ai -and -not $aiOnly) { $aiOnly = $ip }
}
$geminiState = 'dead'
if ($gemini) {
  $geminiState = 'clean'
  Log "Gemini: чистый адрес $gemini"
} elseif ($aiOnly) {
  $geminiState = 'ai-only'
  $gemini = $aiOnly
  Log "Gemini: веб-чат отдаёт /sorry везде, выбран $aiOnly только ради AI Studio"
  Alert 'gemini-sorry' 'GeoHide: Gemini-чат недоступен' 'Все адреса отдают google.com/sorry. Живой только AI Studio. Скорее всего, Google ограничил эти IP, настраивать нечего.'
} else {
  Log 'Gemini: подходящего адреса нет, оставляю прежний'
  Alert 'gemini-dead' 'GeoHide: Gemini лёг' 'Ни веб-чат, ни AI Studio не отвечают ни на одном адресе. Нужен свежий адрес через DoH.'
}
if (-not $gemini) { $gemini = $cur.GEMINI }   # нет лучшего - оставляем прежний

# --- 3. нужно ли обновлять health.txt ---
if (-not $ForceCommit -and $main -eq $cur.MAIN -and $alt -eq $cur.ALT -and $gemini -eq $cur.GEMINI) {
  Log "Без изменений: MAIN=$main ALT=$alt GEMINI=$gemini ($geminiState)"
  exit 0
}
$body = @("# Пишется tools/geohide-probe.ps1 с ПК пользователя (проверка с его провайдера).",
          "# checked $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
          "# gemini: $geminiState",
          "MAIN $main $($scores[$main])",
          "ALT $alt $($scores[$alt])")
if ($gemini) { $body += "GEMINI $gemini" }
$text = ($body -join "`n") + "`n"
Log "Изменение: MAIN $($cur.MAIN) -> $main, ALT $($cur.ALT) -> $alt, GEMINI $($cur.GEMINI) -> $gemini"
if ($DryRun) { Log 'DryRun: коммит не делаю'; Write-Host $text; exit 0 }

$payload = @{
  message = "health: MAIN $main, ALT $alt, GEMINI $gemini ($geminiState)"
  content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text))
  branch  = $Branch
}
if ($sha) { $payload.sha = $sha }
try {
  Invoke-RestMethod -Method Put -Uri $Api -Headers $Headers -Body ($payload | ConvertTo-Json) -ContentType 'application/json; charset=utf-8' -ErrorAction Stop | Out-Null
  Log 'health.txt обновлён, сборка в Actions запущена'
} catch {
  Log "Не удалось записать health.txt: $($_.Exception.Message)"
  Alert 'commit-fail' 'GeoHide: не удалось обновить health.txt' "Проверь токен: $($_.Exception.Message)"
  exit 1
}

# локальная копия в клоне, чтобы он не расходился с форком
try { [IO.File]::WriteAllText($HealthFile, $text, (New-Object System.Text.UTF8Encoding($false))) } catch {}

# --- 4. сразу запускаем DnsConf, чтобы NextDNS обновился без ожидания крона ---
if (-not $DryRun) {
  $d = @{ event_type = 'geohide-updated'; client_payload = @{ main = $main; alt = $alt; gemini = $gemini; gemini_state = $geminiState } }
  try {
    Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$DispatchRepo/dispatches" -Headers $Headers -Body ($d | ConvertTo-Json -Depth 3) -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Log "DnsConf запущен через repository_dispatch"
  } catch {
    Log "Не удалось запустить DnsConf: $($_.Exception.Message). Обновит крон."
  }
}
exit 0
