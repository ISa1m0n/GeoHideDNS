<#
 geohide-probe.ps1 - проверка прокси GeoHide с ПК пользователя (с его провайдера).
 Раннер GitHub в США не видит блокировок РКН, поэтому живость адресов проверяется здесь.

 Что делает:
  1. Берёт "ядро" EU-адресов GeoHide (IP, которые стоят почти у каждого домена EU-hosts).
  2. Для каждого проверяет TLS до claude.ai, chatgpt.com и platform.claude.com (curl --resolve).
  3. Выбирает MAIN (самый быстрый живой) и ALT (второй), а для Gemini ищет адрес без /sorry
     среди текущего GEMINI, адресов из DoH (dns.dagami.ru, dns.zapret.moe) и ядра.
  4. Если результат отличается от health.txt в форке, коммитит новый health.txt через GitHub API.
     Коммит запускает workflow, тот пересобирает hosts-ai.txt, дальше DnsConf обновляет NextDNS.

 Пропускает проверку, если включён VPN-адаптер или запущен zapret (winws): результат был бы ложным.
 Токен: fine-grained, только репозиторий ISa1m0n/GeoHideDNS, право Contents: Read and write.
 Лежит рядом со скриптом в файле geohide-probe.token (одна строка).

 Параметры: -DryRun (ничего не коммитить), -Force (не пропускать при VPN/zapret).
#>
param([switch]$DryRun, [switch]$Force)

$Repo      = 'ISa1m0n/GeoHideDNS'
$Branch    = 'main'
$TokenFile = Join-Path $PSScriptRoot 'geohide-probe.token'
$LogFile   = Join-Path $PSScriptRoot 'geohide-probe.log'
$EuHosts   = 'https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/eu/hosts'
$TestDomains = 'claude.ai', 'chatgpt.com', 'platform.claude.com'
$DohServers  = 'https://dns.dagami.ru/dns-query', 'https://dns.zapret.moe/dns-query'
$Api = "https://api.github.com/repos/$Repo/contents/health.txt"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Log($msg) {
  $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $msg
  Write-Host $line
  try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch {}
  # не даём логу расти бесконечно
  try { if ((Get-Item $LogFile).Length -gt 512KB) { $keep = Get-Content $LogFile -Tail 400; Set-Content -Path $LogFile -Value $keep -Encoding UTF8 } } catch {}
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
  if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { Log 'health.txt в форке ещё нет, будет создан' }
  else { Log "Не удалось прочитать health.txt: $($_.Exception.Message)"; exit 1 }
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

# --- Gemini: ответ без редиректа на /sorry и живой AI Studio ---
function Test-Gemini([string]$ip) {
  $r = & curl.exe -s --connect-timeout 4 -m 12 -o NUL -w '%{http_code} %{redirect_url}' --resolve "gemini.google.com:443:$ip" 'https://gemini.google.com/' 2>$null
  $r = "$r".Trim()
  if ($r -notmatch '^(200|302|301)') { return $false }
  if ($r -match 'sorry') { return $false }
  $a = & curl.exe -s --connect-timeout 4 -m 8 -o NUL -w '%{http_code}' --resolve "aistudio.google.com:443:$ip" 'https://aistudio.google.com/' 2>$null
  return ("$a" -ne '000')
}

# --- 1. MAIN / ALT ---
$scores = @{}
foreach ($ip in $core) {
  $s = Test-Proxy $ip
  if ($null -ne $s) { $scores[$ip] = $s }
}
$ranked = @($scores.Keys | Sort-Object { $scores[$_] })
Log ("EU-адреса: " + (($core | ForEach-Object { if ($scores.ContainsKey($_)) { "$_=$($scores[$_])мс" } else { "$_=мертв" } }) -join '  '))
if ($ranked.Count -eq 0) { Log 'Ни один EU-адрес не отвечает, health.txt не трогаю'; exit 0 }

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
  $ip = & curl.exe -s -m 10 --doh-url $d -o NUL -w '%{remote_ip}' 'https://gemini.google.com/' 2>$null
  $ip = "$ip".Trim()
  if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$' -and -not $cand.Contains($ip)) { $cand.Add($ip) }
}
foreach ($ip in $ranked) { if (-not $cand.Contains($ip)) { $cand.Add($ip) } }
$gemini = $null
foreach ($ip in $cand) { if (Test-Gemini $ip) { $gemini = $ip; break } }
Log ("Gemini: кандидаты " + ($cand -join ', ') + " -> " + $(if ($gemini) { $gemini } else { 'подходящего нет' }))
if (-not $gemini) { $gemini = $cur.GEMINI }   # нет лучшего - оставляем прежний

# --- 3. нужно ли обновлять health.txt ---
if ($main -eq $cur.MAIN -and $alt -eq $cur.ALT -and $gemini -eq $cur.GEMINI) {
  Log "Без изменений: MAIN=$main ALT=$alt GEMINI=$gemini"
  exit 0
}
$body = @("# Пишется tools/geohide-probe.ps1 с ПК пользователя (проверка с его провайдера).",
          "# checked $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
          "MAIN $main $($scores[$main])",
          "ALT $alt $($scores[$alt])")
if ($gemini) { $body += "GEMINI $gemini" }
$text = ($body -join "`n") + "`n"
Log "Изменение: MAIN $($cur.MAIN) -> $main, ALT $($cur.ALT) -> $alt, GEMINI $($cur.GEMINI) -> $gemini"
if ($DryRun) { Log 'DryRun: коммит не делаю'; Write-Host $text; exit 0 }

$payload = @{
  message = "health: MAIN $main, ALT $alt, GEMINI $gemini"
  content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text))
  branch  = $Branch
}
if ($sha) { $payload.sha = $sha }
try {
  Invoke-RestMethod -Method Put -Uri $Api -Headers $Headers -Body ($payload | ConvertTo-Json) -ContentType 'application/json; charset=utf-8' -ErrorAction Stop | Out-Null
  Log 'health.txt обновлён, сборка в Actions запущена'
} catch { Log "Не удалось записать health.txt: $($_.Exception.Message)"; exit 1 }
