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

touch bad-ips.txt pin-ips.txt extra-domains.txt us-domains.txt

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
' bad-ips.txt pin-ips.txt filtered.tmp > "$OUT.new"

if ! grep -qE '^[0-9]' "$OUT.new"; then
  echo "Ни одной записи не осталось, проверь sections.txt" >&2
  exit 1
fi

mv "$OUT.new" "$OUT"
rm -f upstream.tmp upstream-us.tmp filtered.tmp filtered.us.tmp
echo "Готово: $(grep -cE '^[0-9]' "$OUT") записей"
