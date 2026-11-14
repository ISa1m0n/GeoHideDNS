<div align="center">

# hosts-ai для GeoHideDNS

**Компактный hosts-список AI- и dev-сервисов, собранный из публичного GeoHide.**

[![Update filtered GeoHide hosts](https://github.com/ISa1m0n/GeoHideDNS/actions/workflows/update-hosts.yml/badge.svg?branch=main)](https://github.com/ISa1m0n/GeoHideDNS/actions/workflows/update-hosts.yml)

</div>

---

## Что это

[GeoHide](https://github.com/Internet-Helper/GeoHideDNS) — публичный Smart DNS: он отдаёт
hosts-файл с адресами сервисов, которые не открываются напрямую. Файл большой — сотни
доменов, часть которых не нужна, часть уже мертва.

Этот форк собирает из него **свой список** — `hosts-ai.txt`: только нужные разделы,
только рабочие адреса, плюс пара ручных закреплений. Пересобирается раз в сутки
и после каждого изменения конфигов.

## Что получается

На 14.11.2026 — **297 записей** в 30 разделах:

| IP | Записей | Что это |
|---|---:|---|
| `37.221.93.141` | 283 | основной EU-узел GeoHide |
| `89.169.35.124` | 12 | Gemini, см. `custom-hosts.txt` |
| `5.175.161.40` | 2 | `www.deezer.com`, `www.last.fm` |

Актуальное число всегда видно в шапке последнего коммита `hosts-ai.txt`.

## Как работает сборка

`filter.sh` запускается в GitHub Actions и проходит пять шагов:

1. Скачивает свежие `hosts/eu/hosts` и `hosts/us/hosts` из апстрима.
2. Оставляет только разделы из `sections.txt`. Если раздел переименовали — сборка
   падает с ошибкой, а не выкидывает сервис молча.
3. Добавляет домены из `extra-domains.txt` — из любых разделов, независимо от выбора.
4. Подменяет домены из `us-domains.txt` строками US-hosts с указанным IP.
5. Выкидывает адреса из `bad-ips.txt`, применяет закрепления из `pin-ips.txt`,
   последним слоем — `custom-hosts.txt`.

Результат (`hosts-ai.txt`) коммитит бот.

## Структура

| Файл | Роль |
|---|---|
| `hosts-ai.txt` | **готовый список** — его и забирают |
| `sections.txt` | какие разделы апстрима оставить |
| `extra-domains.txt` | домены вне выбранных разделов |
| `us-domains.txt` | домены, которые берутся из US-hosts |
| `pin-ips.txt` | закрепить домен и его поддомены на одном IP |
| `custom-hosts.txt` | ручные записи поверх всей сборки |
| `bad-ips.txt` | адреса, которые нельзя использовать |
| `filter.sh` | сам сборщик |
| `.github/workflows/` | расписание, пересборка по push, keepalive |

## Как применить

### Windows

Дописать записи из `hosts-ai.txt` в `C:\Windows\System32\drivers\etc\hosts`
(нужны права администратора). Удобнее держать их отдельным блоком с маркерами
`BEGIN` / `END`, чтобы обновлять целиком.

### Keenetic

В Web CLI (`<роутер>/a`) — по строке на домен:

```
ip host chatgpt.com 37.221.93.141
```

> **Лимит.** У Keenetic максимум **256** статических записей `ip host`,
> из них 2 служебных. 297 доменов туда не влезают: часть придётся выбрать
> или вынести на NextDNS.

### NextDNS

Через [DnsConf](https://github.com/ISa1m0n/DnsConf): он берёт `hosts-ai.txt`
как источник rewrites и обновляет их по расписанию. Rewrites в NextDNS
действуют на домен **и его поддомены**, поэтому отдельные `www.*` там не нужны.

## Что изменено относительно апстрима

- Выбрано 30 разделов вместо всех. Убраны `Canva`, `Chess`, `Oracle`, `Supercell`:
  GeoHide их не проксирует, а обычный DNS для них лучше.
- `custom-hosts.txt` закрепляет Gemini на `89.169.35.124` — на EU-адресах Google
  отдаёт `google.com/sorry`.
- `us-domains.txt` отключён: US-адреса GeoHide перестали отвечать.
- Удалены служебные копии `lists/` и `hosts/*` — сборка их не использует,
  всё качается из апстрима.

## Как менять

- **Добавить сервис** — дописать раздел в `sections.txt` (название должно точно
  совпадать с заголовком `# ...` в `hosts/eu/hosts` апстрима).
- **Один домен** — добавить в `extra-domains.txt`.
- **Свой IP** — `custom-hosts.txt`, формат `домен IP`.
- **Убрать адрес** — `bad-ips.txt`.

После правки пересборка стартует сама (workflow слушает `push` по этим файлам).

## Ссылки

- Апстрим: [Internet-Helper/GeoHideDNS](https://github.com/Internet-Helper/GeoHideDNS)
- Настройка NextDNS: [ISa1m0n/DnsConf](https://github.com/ISa1m0n/DnsConf)
