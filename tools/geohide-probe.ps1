<#
 geohide-probe.ps1 - проверка прокси GeoHide с ПК пользователя (с его провайдера).
 Раннер GitHub в США не видит блокировок РКН, поэтому живость адресов проверяется здесь.

 Что делает:
  1. Полная проверка (раз в 3 часа): берёт "ядро" EU-адресов GeoHide (IP, которые стоят
     почти у каждого домена EU-hosts) и проверяет TLS до claude.ai, chatgpt.com и
     platform.claude.com, выбирает MAIN (самый быстрый живой) и ALT (второй).
     Если все EU-адреса молчат, берёт адреса из сторонних DoH (doh-servers.txt).
  2. Между полными проверками (запуск каждый час) только пингует текущие MAIN и ALT
     и при их смерти запускает полную проверку. Полсотни TLS-запросов каждый час не нужны.
  3. Для Gemini ищет адрес без google.com/sorry: сначала среди DoH-ответов, потом среди
     проверенных адресов. Статус Gemini пишется комментарием в health.txt:
     clean / ai-only / dead.
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
$EuHosts      = 'https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/eu/hosts'
$TestDomains  = 'claude.ai', 'chatgpt.com', 'platform.claude.com'
# Сторонние DoH-резолверы: адреса для Gemini и запасной пул, если GeoHide замолчит.
# Список лежит в doh-servers.txt, чтобы добавлять сервисы без правки кода.
$DohFile      = Join-Path $PSScriptRoot 'doh-servers.txt'
$DohServers   = @()
if (Test-Path $DohFile) {
  $DohServers = @(Get-Content $DohFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -like 'http*' })
}
if ($DohServers.Count -eq 0) {
  $DohServers = @('https://dns.dagami.ru/dns-query', 'https://dns.zapret.moe/dns-query', 'https://dns.bezmezhau.com/dns-query')
}
$DohTimeout   = 4
$FullScanEvery = 3 * 3600    # полный перебор адресов не чаще раза в 3 часа
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

# Состояние: время последней полной проверки и отметки показанных уведомлений.
function Read-State() {
  $s = @{}
  try {
    if (Test-Path $StateFile) {
      foreach ($l in (Get-Content $StateFile)) {
        if ($l -match '^(\S+)\s+(\d+)$') { $s[$Matches[1]] = [long]$Matches[2] }
      }
    }
  } catch {}
  return $s
}
function Write-State($s) {
  try { ($s.Keys | ForEach-Object { "$_ $($s[$_])" }) | Set-Content -Path $StateFile -Encoding UTF8 } catch {}
}

# Уведомление в трей. Ничего не устанавливаем, обходимся WinForms.
# Одно и то же событие показываем не чаще раза в $NotifyEvery секунд.
function Alert([string]$key, [string]$title, [string]$text) {
  if ($NoNotify) { return }
  $state = Read-State
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  if ($state.ContainsKey($key) -and ($now - $state[$key]) -lt $NotifyEvery) { return }
  $state[$key] = $now
  Write-State $state
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

# --- быстрая проверка: живы ли текущие адреса (один запрос на домен) ---
function Test-Alive([string]$ip) {
  if (-not $ip) { return $false }
  foreach ($d in @('claude.ai', 'chatgpt.com')) {
    $code = ("" + (& curl.exe -s --connect-timeout 4 -m 8 -o NUL -w '%{http_code}' --resolve "${d}:443:$ip" "https://$d" 2>$null)).Trim()
    # claude.ai через прокси честно отдаёт 403: значит TLS прошёл и запрос дошёл
    if ($code -notmatch '^(200|301|302|403)$') { return $false }
  }
  return $true
}

# --- ответы сторонних DoH: уникальные адреса для домена ---
function Get-DohAddress([string]$domain) {
  $out = New-Object System.Collections.Generic.List[string]
  foreach ($d in $DohServers) {
    if (-not $d) { continue }
    $ip = ("" + (& curl.exe -s --connect-timeout 3 -m $DohTimeout --doh-url $d -o NUL -w '%{remote_ip}' "https://$domain/" 2>$null)).Trim()
    if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
      Log "  DoH $d -> $ip ($domain)"
      if (-not $out.Contains($ip)) { $out.Add($ip) }
    }
  }
  return $out
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
# Между полными переборами (раз в 3 часа) скрипт запускается каждый час и только
# проверяет, живы ли текущие адреса. Если да - выходит, ничего не коммитя.
$state = Read-State
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$lastFull = 0
if ($state.ContainsKey('fullscan')) { $lastFull = [long]$state['fullscan'] }
$source = 'GeoHide EU'

if (($now - $lastFull) -lt $FullScanEvery) {
  $okMain = Test-Alive $cur.MAIN
  $okAlt  = Test-Alive $cur.ALT
  if ($okMain -and $okAlt) {
    $left = [int](($FullScanEvery - ($now - $lastFull)) / 60)
    Log "Быстрая проверка: MAIN=$($cur.MAIN) жив, ALT=$($cur.ALT) жив. Полный перебор не раньше чем через $left мин"
    exit 0
  }
  $stMain = 'мертв'; if ($okMain) { $stMain = 'жив' }
  $stAlt  = 'мертв'; if ($okAlt)  { $stAlt  = 'жив' }
  Log "Быстрая проверка: MAIN=$($cur.MAIN) $stMain, ALT=$($cur.ALT) $stAlt. Запускаю полный перебор"
}

# --- ядро EU-адресов GeoHide ---
$counts = @{}
$eu = (& curl.exe -s -m 30 $EuHosts) -split "`n"
foreach ($l in $eu) {
  if ($l -match '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\S') { $counts[$Matches[1]] = 1 + [int]$counts[$Matches[1]] }
}
$core = @($counts.Keys | Where-Object { $counts[$_] -ge 500 })

$scores = @{}
foreach ($ip in $core) {
  $s = Test-Proxy $ip
  if ($null -ne $s) { $scores[$ip] = $s }
}
if ($core.Count -gt 0) {
  Log ("EU-адреса: " + (($core | ForEach-Object { if ($scores.ContainsKey($_)) { "$_=$($scores[$_])мс" } else { "$_=мертв" } }) -join '  '))
} else {
  Log 'EU-hosts недоступен, смотрю только ответы сторонних DoH'
}

# Аварийный режим: ни один адрес GeoHide не ответил. Берём кандидатов у сторонних
# резолверов, но проверяем тем же тестом: адрес обязан проксировать все тестовые домены.
if ($scores.Count -eq 0) {
  $pool = @(Get-DohAddress 'claude.ai')
  foreach ($ip in (Get-DohAddress 'chatgpt.com')) { if ($pool -notcontains $ip) { $pool += $ip } }
  foreach ($ip in $pool) {
    $s = Test-Proxy $ip
    if ($null -ne $s) { $scores[$ip] = $s }
  }
  $source = 'DoH'
  if ($pool.Count -gt 0) {
    Log ("Ответы DoH: " + (($pool | ForEach-Object { if ($scores.ContainsKey($_)) { "$_=$($scores[$_])мс" } else { "$_=мертв" } }) -join '  '))
  }
}

$ranked = @($scores.Keys | Sort-Object { $scores[$_] })
if ($ranked.Count -eq 0) {
  Log 'Живых адресов нет ни в GeoHide, ни в DoH, health.txt не трогаю'
  Alert 'main-dead' 'GeoHide: живых адресов нет' 'Ни один адрес не прошёл проверку TLS: ни EU-серверы GeoHide, ни ответы сторонних DoH. Проверь провайдера и zapret.'
  exit 2
}

$main = $ranked[0]
# не прыгаем между адресами без нужды: текущий MAIN остаётся, пока жив и не сильно медленнее лучшего
if ($cur.MAIN -and $scores.ContainsKey($cur.MAIN) -and $scores[$cur.MAIN] -le ($scores[$main] * 1.5 + 60)) { $main = $cur.MAIN }
$alt = $null
if ($cur.ALT -and $cur.ALT -ne $main -and $scores.ContainsKey($cur.ALT)) { $alt = $cur.ALT }
if (-not $alt) { $alt = $ranked | Where-Object { $_ -ne $main } | Select-Object -First 1 }
if (-not $alt) { $alt = $main }

# перебор удался - запоминаем время, следующие 3 часа только быстрая проверка
$state['fullscan'] = $now
Write-State $state
Log "Перебор закончен (источник $source): MAIN=$main $($scores[$main])мс, ALT=$alt $($scores[$alt])мс"

# --- 2. GEMINI ---
$cand = New-Object System.Collections.Generic.List[string]
if ($cur.GEMINI) { $cand.Add($cur.GEMINI) }
foreach ($ip in (Get-DohAddress 'gemini.google.com')) { if (-not $cand.Contains($ip)) { $cand.Add($ip) } }
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
          "# source: $source",
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

# --- 4. ждём, пока бот пересоберёт hosts-ai.txt ---
# Диспатч сразу после коммита health.txt срабатывал раньше пересборки: DnsConf
# успевал прочитать старый hosts-ai.txt и накатить прежние адреса. Поэтому
# дожидаемся, пока в файле появятся новые значения (Contents API не кэшируется).
$needMain = ($main -ne $cur.MAIN)
$needAlt  = ($alt -ne $cur.ALT)
$needGem  = ($gemini -ne $cur.GEMINI)
if ($needMain -or $needAlt -or $needGem) {
  $deadline = (Get-Date).AddMinutes(4)
  $ready = $false
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 10
    try {
      $h2 = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/contents/hosts-ai.txt?ref=$Branch" -Headers $Headers -ErrorAction Stop
      $ht = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($h2.content -replace '\s', '')))
      $ok = $true
      if ($needMain) { $ok = $ok -and ([regex]::Matches($ht, "(?m)^$([regex]::Escape($main))\s")).Count -ge 200 }
      if ($needAlt)  { $ok = $ok -and ($ht -match "(?m)^$([regex]::Escape($alt))\s+last\.fm\s*$") }
      if ($needGem)  { $ok = $ok -and ($ht -match "(?m)^$([regex]::Escape($gemini))\s+gemini\.google\.com\s*$") }
      if ($ok) { $ready = $true; break }
    } catch {}
  }
  if ($ready) { Log 'hosts-ai.txt пересобран с новыми адресами' }
  else { Log 'Пересборка не успела за 4 минуты, запускаю DnsConf на том, что есть' }
}

# --- 5. запускаем DnsConf, чтобы NextDNS обновился без ожидания крона ---
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
