#!/usr/bin/env bash
# Скачивает свежий hosts GeoHide (EU), оставляет разделы из sections.txt,
# добавляет отдельные домены из extra-domains.txt (из любых разделов),
# подменяет часть доменов строками из US-hosts по списку us-domains.txt,
# выкидывает плохие IP из bad-ips.txt и применяет исключения из pin-ips.txt.
# Первый IP каждого домена попадает в NextDNS Rewrites (так работает DnsConf).
set -euo pipefail

SRC="https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/eu/hosts"
SRC_US="https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/us/hosts"
OUT="hosts-ai.txt"

touch bad-ips.txt pin-ips.txt extra-domains.txt us-domains.txt custom-hosts.txt skip-domains.txt

curl -fsSL "$SRC" | tr -d '\r' > upstream.tmp

if [ "$(wc -l < upstream.tmp)" -lt 500 ]; then
  echo "Файл слишком короткий, прерываю" >&2
  exit 1
fi

# 0. проверка: все разделы из sections.txt должны существовать в оригинале.
#    Если автор GeoHide переименовал раздел, лучше громко упасть (красный крестик
#    в Actions), чем тихо выкинуть сервис из hosts-ai.txt.
missing=0
while IFS= read -r s || [ -n "$s" ]; do
  s="$(printf '%s' "$s" | sed 's/[[:space:]]*$//')"
  case "$s" in ''|\#*) continue ;; esac
  if ! grep -qxF "# $s" upstream.tmp; then
    echo "Раздел не найден в оригинале: $s" >&2
    echo "  похожие заголовки:" >&2
    grep -iF "# ${s%% *}" upstream.tmp | sed 's/^/    /' >&2 || true
    missing=1
  fi
done < sections.txt
if [ "$missing" -ne 0 ]; then
  echo "Исправь названия в sections.txt и запусти снова" >&2
  exit 1
fi

# 1. оставляем только нужные разделы
awk '
  NR == FNR { sub(/[ \t]+$/, ""); if ($0 != "" && $0 !~ /^#/) want[$0] = 1; next }
  /^# /     { name = substr($0, 3); sub(/[ \t]+$/, "", name); on = (name in want); if (on) print; next }
  on && NF >= 2 && $1 !~ /^#/ { print }
' sections.txt upstream.tmp > filtered.tmp

# 1b. отдельные домены из extra-domains.txt (из любых разделов оригинала)
awk '
  FILENAME == ARGV[1] { sub(/[ \t\r]+$/, ""); if ($0 != "" && $0 !~ /^#/) want[$0] = 1; next }
  NF >= 2 && $1 !~ /^#/ && ($2 in want) { print }
' extra-domains.txt upstream.tmp >> filtered.tmp

# 1c. домены из US-hosts (us-domains.txt, формат: "домен IP").
#     В US-hosts у домена несколько IP, поэтому берётся только строка с указанным
#     IP. EU-строки этих доменов убираются, вместо них идёт строка из US.
#     Если нужной строки в US-hosts нет, сборка падает (как и с разделами).
if tr -d '\r' < us-domains.txt | grep -qE '^[[:space:]]*[^#[:space:]]'; then
  curl -fsSL "$SRC_US" | tr -d '\r' > upstream-us.tmp

  if [ "$(wc -l < upstream-us.tmp)" -lt 500 ]; then
    echo "US-файл слишком короткий, прерываю" >&2
    exit 1
  fi

  missing=0
  while read -r d ip _ || [ -n "${d:-}" ]; do
    case "${d:-}" in ''|\#*) continue ;; esac
    if [ -z "${ip:-}" ]; then
      echo "В us-domains.txt у домена $d не указан IP" >&2
      missing=1
      continue
    fi
    if ! awk -v d="$d" -v ip="$ip" '$1 == ip && $2 == d { f = 1 } END { exit !f }' upstream-us.tmp; then
      echo "В US-hosts нет строки: $ip $d" >&2
      missing=1
    fi
  done < <(tr -d '\r' < us-domains.txt)
  if [ "$missing" -ne 0 ]; then
    echo "Исправь us-domains.txt (домен или IP) и запусти снова" >&2
    exit 1
  fi

  # убираем EU-строки этих доменов
  awk '
    FILENAME == ARGV[1] { sub(/\r$/, ""); if ($0 !~ /^[ \t]*#/ && NF >= 2) want[$1] = $2; next }
    /^#/ || NF < 2 { print; next }
    !($2 in want) { print }
  ' us-domains.txt filtered.tmp > filtered.us.tmp
  mv filtered.us.tmp filtered.tmp

  # добавляем US-строки с нужным IP
  awk '
    FILENAME == ARGV[1] { sub(/\r$/, ""); if ($0 !~ /^[ \t]*#/ && NF >= 2) want[$1] = $2; next }
    NF >= 2 && $1 !~ /^#/ && ($2 in want) && $1 == want[$2] && !seen[$2]++ { print }
  ' us-domains.txt upstream-us.tmp >> filtered.tmp
fi

# 1e. Домены, которые всё равно блокирует список рекламы (переменная BLOCK у DnsConf).
#     NextDNS отвечает для них «Filtered», rewrite до них не доходит, поэтому держать
#     их в списке бессмысленно: они только путают сверку. Формат: домен, действует
#     и на поддомены.
if tr -d '\r' < skip-domains.txt | grep -qE '^[[:space:]]*[^#[:space:]]'; then
  awk '
    FILENAME == ARGV[1] {
      sub(/\r$/, ""); sub(/[[:space:]]*#.*$/, "")
      if ($0 != "" && $0 !~ /^[[:space:]]*#/) { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); skip[$0] = 1 }
      next
    }
    /^#/ || NF < 2 { print; next }
    {
      dom = $2; drop = 0
      for (s in skip) {
        if (dom == s || (length(dom) > length(s) && substr(dom, length(dom) - length(s)) == "." s)) { drop = 1; break }
      }
      if (!drop) print
    }
  ' skip-domains.txt filtered.tmp > filtered.skip.tmp
  mv filtered.skip.tmp filtered.tmp
fi

# 1d. Живые адреса. defaults.txt задаёт значения по умолчанию, health.txt (его пишет
#     tools/geohide-probe.ps1 с ПК пользователя, проверка идёт с его провайдера) их
#     перекрывает. Ключи: MAIN (основной EU-адрес), ALT (второй EU-адрес для разноса
#     www и apex), GEMINI (адрес для Gemini и AI Studio из custom-hosts.txt).
MAIN=""; ALT=""; GEMINI=""
for f in defaults.txt health.txt; do
  [ -f "$f" ] || continue
  while read -r key val _ || [ -n "${key:-}" ]; do
    case "${key:-}" in
      MAIN)   MAIN="${val:-}" ;;
      ALT)    ALT="${val:-}" ;;
      GEMINI) GEMINI="${val:-}" ;;
    esac
  done < <(tr -d '\r' < "$f")
done
IPRE='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
if ! [[ "$MAIN" =~ $IPRE ]]; then echo "MAIN не задан или не IP: '$MAIN'" >&2; exit 1; fi
if ! [[ "$ALT" =~ $IPRE ]]; then ALT="$MAIN"; fi
if ! [[ "$GEMINI" =~ $IPRE ]]; then GEMINI=""; fi

# "ядро" прокси: IP, которые стоят почти у каждого домена EU-hosts
awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { c[$1]++ } END { for (i in c) if (c[i] >= 500) print i }' upstream.tmp > core-ips.tmp
if ! grep -qxF "$MAIN" core-ips.tmp; then
  echo "MAIN $MAIN не найден среди основных IP EU-hosts: $(tr '\n' ' ' < core-ips.tmp)" >&2
  exit 1
fi
# плохие IP: bad-ips.txt + всё ядро, кроме MAIN (так все домены идут на один живой адрес)
{ tr -d '\r' < bad-ips.txt | sed 's/[[:space:]]*$//' | grep -vE '^(#|$)' || true; cat core-ips.tmp; } \
  | sort -u | grep -vxF "$MAIN" > bad.tmp
sed -e "s/@MAIN/$MAIN/g" -e "s/@ALT/$ALT/g" pin-ips.txt > pin.tmp
if [ -n "$GEMINI" ]; then
  sed "s/@GEMINI/$GEMINI/g" custom-hosts.txt > custom.tmp
else
  grep -v '@GEMINI' custom-hosts.txt > custom.tmp || true
fi
echo "Адреса: MAIN=$MAIN ALT=$ALT GEMINI=${GEMINI:-нет}"

# 2. плохие IP и закреплённые IP
awk '
  FILENAME == ARGV[1] { sub(/[ \t\r]+$/, ""); if ($0 != "" && $0 !~ /^#/) bad[$0] = 1; next }
  FILENAME == ARGV[2] { if ($0 !~ /^#/ && NF >= 2) { np++; pd[np] = $1; pip[np] = $2 } next }
  /^#/ || NF < 2 { print; next }
  {
    ip = $1; dom = $2; pinned = 0
    for (k = 1; k <= np; k++) {
      p = pd[k]
      if (dom == p || (length(dom) > length(p) && substr(dom, length(dom) - length(p)) == "." p)) {
        pinned = 1
        if (ip == pip[k]) print
        break
      }
    }
    if (!pinned && !(ip in bad)) print
  }
' bad.tmp pin.tmp filtered.tmp > "$OUT.new"

# 3. Ручные закрепления из custom-hosts.txt (формат: "домен IP"), последним шагом.
#    IP берётся как есть, без проверки по hosts GeoHide. Старые строки этих доменов
#    в результате удаляются, вместо них в конец добавляются строки из custom-hosts.txt.
if tr -d '\r' < custom.tmp | grep -qE '^[[:space:]]*[^#[:space:]]'; then
  awk '
    FILENAME == ARGV[1] {
      sub(/\r$/, "")
      if ($0 !~ /^[ \t]*#/ && NF >= 2) { if (!($1 in want)) order[++n] = $1; want[$1] = $2 }
      next
    }
    /^#/ || NF < 2 { print; next }
    !($2 in want) { print }
    END {
      print "# Custom (custom-hosts.txt)"
      for (i = 1; i <= n; i++) print want[order[i]], order[i]
    }
  ' custom.tmp "$OUT.new" > "$OUT.custom"
  mv "$OUT.custom" "$OUT.new"
fi

# 4. Защита от массовой потери записей: сломанный апстрим или неудачная правка
#    sections.txt не должны превращать живой список в огрызок. Старый hosts-ai.txt
#    в этом случае остаётся, DnsConf продолжает работать по нему.
new=$(grep -cE '^[0-9]' "$OUT.new" || true)
prev=$(grep -cE '^[0-9]' "$OUT" 2>/dev/null || true)
if [ "$new" -lt 200 ]; then
  echo "Собралось всего $new записей (ожидается больше 200), сборку не применяю" >&2
  exit 1
fi
if [ "${prev:-0}" -ge 200 ] && [ "$new" -lt $((prev * 8 / 10)) ]; then
  echo "Записей стало $new против $prev - потеря больше 20%, сборку не применяю" >&2
  echo "Если так и задумано, удали hosts-ai.txt и запусти снова" >&2
  exit 1
fi

mv "$OUT.new" "$OUT"
rm -f upstream.tmp upstream-us.tmp filtered.tmp filtered.us.tmp filtered.skip.tmp "$OUT.custom" core-ips.tmp bad.tmp pin.tmp custom.tmp
echo "Готово: $(grep -cE '^[0-9]' "$OUT") записей"
