# Custom Graylog MCP server

Dockerizovaný MCP server pre Graylog s natívnymi nástrojmi, Streamable HTTP transportom a voliteľným OpenAI orchestration nástrojom `ask_graylog`.

## Spustenie

```powershell
Copy-Item example.env .env
# uprav Graylog URL a API token; OPENAI_API_KEY je voliteľný
docker compose up -d --build
```

Vďaka `pull_policy: build` funguje aj jednoduché `docker compose up -d`; Compose image najprv lokálne zostaví a nebude ho hľadať v Docker registry.

Na lokálne overenie Compose konfigurácie bez produkčných údajov je pripravený [example.env](example.env):

```powershell
docker compose --env-file example.env config
```

## Voliteľné HTTPS cez Caddy

HTTP funguje aj bez Caddy. HTTPS proxy sa spúšťa samostatným Compose profilom:

```powershell
docker compose --profile https up -d --build
```

Nastavenia Caddy sú v `.env`:

- `CADDY_DOMAIN` je doména, na ktorej bude služba dostupná. Pri verejnej doméne Caddy automaticky vybaví a obnovuje certifikát Let’s Encrypt; DNS musí smerovať na server a porty 80/443 musia byť dostupné.
- `CADDY_EMAIL` je kontaktný e-mail pre ACME registráciu.
- `CADDY_TLS_DIRECTIVE` nechajte prázdne pre Let’s Encrypt. Pre vlastný certifikát nastavte napr. `tls /etc/caddy/certs/fullchain.pem /etc/caddy/certs/privkey.pem` a súbory vložte do adresára `CADDY_CERTS_DIR` (predvolene `./caddy/certs`).
- `CADDY_HTTP_PORT`, `CADDY_WEBUI_HTTPS_PORT` a `CADDY_MCP_HTTPS_PORT` menia porty na hostiteľovi. Predvolené HTTPS porty sú 443 pre WebUI a 8443 pre MCP.

Caddy uchováva ACME účty a certifikáty v `./caddy/data`, takže automatická obnova pretrvá aj po reštarte kontajnera. Po zmene certifikátu stačí reštartovať Caddy: `docker compose --profile https restart caddy`.

HTTPS endpointy sú oddelené: WebUI je na `https://logs.example.com/` a MCP na `https://logs.example.com:8443/mcp`. WebUI port MCP cestu odmieta a MCP port sprístupňuje iba `/mcp` a `/health`. Pri vlastnom certifikáte musí `CADDY_DOMAIN` zodpovedať menu v certifikáte.

MCP endpoint pre agenta je `http://localhost:8000/mcp` (hodnoty portu a cesty sú v `.env`). Health check je na `/health`.
Web UI is available at `http://localhost:8000/` and uses Basic Auth from `UI_USERNAME` and `UI_PASSWORD`. It contains `Graylog Servers`, `MCP Clients`, `Query Rules`, and `Audit Log` sections. The floating navigation changes to a hamburger menu on mobile. Graylog servers can be added, edited, and tested; leaving the API token blank while editing preserves the existing token.

Query rules are managed in SQLite from the `Query Rules` UI section. A rule controls the Lucene filter, message/aggregation mode, time range, result limit, grouping, metrics, time bucket, default template parameters, and agent instructions. Definitions from `queries.yaml` are imported only as initial defaults and can then be edited in the UI.
REST API je dostupné pod `/api/v1` a interaktívna Swagger dokumentácia na `http://localhost:8000/docs`; OpenAPI schéma je na `/openapi.json`.

MCP klient sa pripája na `/mcp` cez `Authorization: Bearer <agent-api-key>`. Každý agent je databázovo viazaný na jeden Graylog server; server sa vyberá podľa API kľúča a klient ho nemôže zmeniť. Admin operácie v UI sú chránené oddelenými `UI_USERNAME`/`UI_PASSWORD` údajmi.

Nový agent dostane API kľúč v odpovedi pri vytvorení. Kľúč si ulož, pretože databáza uchováva iba jeho hash a posledné štyri znaky.

Príklady REST volaní:

```powershell
Invoke-RestMethod http://localhost:8000/api/v1/search/messages -Method Post -ContentType 'application/json' -Body '{"query":"level:3","minutes":15,"limit":20}'
Invoke-RestMethod http://localhost:8000/api/v1/search/aggregate -Method Post -ContentType 'application/json' -Body '{"query":"*","minutes":60,"group_by":[{"field":"service"}],"metrics":[{"function":"count"}]}'
```
Audit databáza SQLite sa ukladá do `./data/audit.db` a eviduje AI otázky/odpovede aj Graylog API volania/odpovede. Retenciu nastavujú `AUDIT_RETENTION_DAYS`, `AUDIT_MAX_ROWS` a `AUDIT_MAX_PAYLOAD_CHARS`; čistenie prebieha pri štarte a po každom zápise.
Audit log obsahuje aj SQLite FTS5 fulltext index. Vo web UI ho možno prehľadávať podľa slov, fráz, prefixov (`timeout*`) a boolean výrazov (`error OR failed`), s voliteľným filtrovaním podľa zdroja.

## Managed query rules

Queries are created and edited in the `Query Rules` section of the Web UI and persisted in SQLite. Supported types are `messages` and `aggregate`. Template parameters such as `${name}` can be supplied through the `run_saved_query` MCP tool. The bundled [queries.yaml](queries.yaml) file is used only to seed an empty database.

Native tools: `search_messages`, `aggregate`, `list_streams`, `list_saved_queries`, `run_saved_query`, and `ask_graylog`.

## Poznámky

Server používa Graylog Search Scripting API endpointy `/api/search/messages` a `/api/search/aggregate`. Graylog autentifikácia používa API token v Basic Auth formáte `TOKEN:token`; nastavuje sa cez `GRAYLOG_API_TOKEN`. Agregačné `group_by` položky používajú Graylog formát, napr. `{field: service}`; časové buckety možno pridať cez `interval`. Pri staršej alebo výrazne customizovanej verzii Graylogu sa endpointy dajú zmeniť v `graylog_mcp/graylog.py`. Do produkcie odporúčam HTTPS/reverse proxy pred MCP endpointom a Graylog používateľa s minimálnymi potrebnými právami.
