#!/usr/bin/env bash
# Скачивает свежий hosts GeoHide (RU), оставляет разделы из sections.txt,
# выкидывает плохие IP из bad-ips.txt и применяет исключения из pin-ips.txt.
# Первый IP каждого домена попадает в NextDNS Rewrites (так работает DnsConf).
set -euo pipefail

SRC="https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts"
OUT="hosts-ai.txt"

touch bad-ips.txt pin-ips.txt

curl -fsSL "$SRC" | tr -d '\r' > upstream.tmp

if [ "$(wc -l < upstream.tmp)" -lt 500 ]; then
  echo "Файл слишком короткий, прерываю" >&2
  exit 1
fi

# 1. оставляем только нужные разделы
awk '
  NR == FNR { sub(/[ \t]+$/, ""); if ($0 != "" && $0 !~ /^#/) want[$0] = 1; next }
  /^# /     { name = substr($0, 3); sub(/[ \t]+$/, "", name); on = (name in want); if (on) print; next }
  on && NF >= 2 && $1 !~ /^#/ { print }
' sections.txt upstream.tmp > filtered.tmp

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
rm -f upstream.tmp filtered.tmp
echo "Готово: $(grep -cE '^[0-9]' "$OUT") записей"
