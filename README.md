# pihole-mcp

MCP-сервер для Pi-hole v6.x (новый `/api` эндпоинт, session-based авторизация через `X-FTL-SID`). Помимо прямого проксирования Pi-hole API даёт несколько составных инструментов для анализа устройств в сети (топ доменов, аномалии, подозрительная активность по NXDOMAIN/block-ratio) — их нет в самом Pi-hole API, это отдельная логика поверх `/api/queries`.

## Инструменты

**Статистика и запросы**

| Инструмент | Описание |
|---|---|
| `get_stats` | Общая статистика: запросов всего, заблокировано, клиентов, доменов в Gravity |
| `get_top_domains` | Топ запрашиваемых/заблокированных доменов |
| `get_top_clients` | Топ клиентов по количеству запросов |
| `search_query_log` | Поиск в логе по домену/IP клиента, с фильтром по времени |
| `get_recently_blocked` | Последние заблокированные запросы |
| `check_domain` | Статус домена — заблокирован ли и в каком списке |

**Анализ устройства**

| Инструмент | Описание |
|---|---|
| `get_client_info` | Профиль клиента: запросы, блокировки, детали |
| `get_recent_queries` | Последние запросы конкретного клиента |
| `analyze_device` | Комплексный анализ: топ доменов, block-ratio, NXDOMAIN-флаги (возможный DNS tunneling/malware) |
| `analyze_anomalies` | Клиенты с аномально высоким числом запросов |

**Списки (allow/deny, exact и regex)**

| Инструмент | Описание |
|---|---|
| `add_to_denylist` / `remove_from_denylist` | Точный домен в чёрный список |
| `add_to_allowlist` | Точный домен в белый список |
| `add_to_denylist_regex` / `remove_from_denylist_regex` | Regex-паттерн в чёрный список |
| `add_to_allowlist_regex` / `remove_from_allowlist_regex` | Regex-паттерн в белый список |

**Локальный DNS**

| Инструмент | Описание |
|---|---|
| `get_local_dns` / `set_local_dns` / `remove_local_dns` | A-записи (override) |
| `get_local_cname_records` / `set_local_cname_record` / `remove_local_cname_record` | CNAME-записи |

**Управление и бэкап**

| Инструмент | Описание |
|---|---|
| `toggle_blocking` / `get_blocking_status` | Включить/выключить блокировку, с таймером авто-включения |
| `gravity_update` | Обновить списки блокировок |
| `teleporter_backup` | Полный бэкап конфигурации (Teleporter) в base64. Только экспорт — восстановление намеренно не реализовано |

## Установка

```bash
git clone <this-repo> pihole-mcp && cd pihole-mcp
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # заполните PIHOLE_URL / PIHOLE_PASSWORD / MCP_SECRET
uvicorn server:app --host 0.0.0.0 --port 8002
```

Systemd-юнит — пример в [`deploy/pihole-mcp.service`](deploy/pihole-mcp.service).

## Security model

- Авторизация — `Authorization: Bearer $MCP_SECRET` на `/mcp`. Пустой `MCP_SECRET` = без проверки (только локальная сеть/VPN).
- `/.well-known/oauth-authorization-server` + `/oauth/authorize` + `/oauth/token` — совместимая заглушка для custom-коннекторов claude.ai, у которых [нет поддержки статического API-ключа](https://claude.com/docs/connectors/building/authentication) — только полноценный OAuth 2.1 или отсутствие авторизации вовсе. Реальную защиту даёт Bearer-токен на `/mcp`. Через Claude Code CLI (`claude mcp add --header ...`) заглушка не нужна.
- `redirect_uri` в `/oauth/authorize` — allowlist (`claude.ai`, `anthropic.com`, `console.anthropic.com`, `localhost`).
- Pi-hole API не умеет фильтровать `/queries` по `client=` на своей стороне — сервер тянет последние N (по умолчанию 5000) записей по всей сети и фильтрует сам, с явным предупреждением в ответе, если окно могло не покрыть всю историю нужного клиента.

## Требования

- Pi-hole v6.x (не v5 — эндпоинты `/api/...` появились только в v6).
- Python 3.11+.

## Лицензия

MIT — см. [LICENSE](LICENSE).
