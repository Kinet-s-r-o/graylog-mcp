# Custom Graylog MCP server

Dockerizovaný MCP server pre Graylog s natívnymi nástrojmi, Streamable HTTP transportom a voliteľným OpenAI orchestration nástrojom `ask_graylog`.

## Spustenie

```powershell
Copy-Item .env.example .env
# uprav Graylog URL a API token; OPENAI_API_KEY je voliteľný
docker compose up -d --build
```

Vďaka `pull_policy: build` funguje aj jednoduché `docker compose up -d`; Compose image najprv lokálne zostaví a nebude ho hľadať v Docker registry.

Na lokálne overenie Compose konfigurácie bez produkčných údajov je pripravený [example.env](example.env):

```powershell
docker compose --env-file example.env config
```

MCP endpoint pre agenta je `http://localhost:8000/mcp` (hodnoty portu a cesty sú v `.env`). Health check je na `/health`.
Webové UI je na `http://localhost:8000/` a používa Basic Auth z premenných `UI_USERNAME` a `UI_PASSWORD`. V UI sa najprv pridá Graylog server (URL + Graylog API token), potom klient/agent s prideleným serverom.
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

## Custom dotazy

Dotazy sa upravujú v [queries.yaml](queries.yaml). Podporované typy sú `messages` a `aggregate`; používajú rovnaké parametre ako Graylog API. Parametre `${name}` možno poslať cez MCP nástroj `run_saved_query`.

Natívne nástroje: `search_messages`, `aggregate`, `list_streams`, `list_saved_queries`, `run_saved_query` a `ask_graylog`. Pri zmene `queries.yaml` stačí súbor upraviť a reštartovať kontajner (`docker compose restart`).

## Poznámky

Server používa Graylog Search Scripting API endpointy `/api/search/messages` a `/api/search/aggregate`. Graylog autentifikácia používa API token v Basic Auth formáte `TOKEN:token`; nastavuje sa cez `GRAYLOG_API_TOKEN`. Agregačné `group_by` položky používajú Graylog formát, napr. `{field: service}`; časové buckety možno pridať cez `interval`. Pri staršej alebo výrazne customizovanej verzii Graylogu sa endpointy dajú zmeniť v `graylog_mcp/graylog.py`. Do produkcie odporúčam HTTPS/reverse proxy pred MCP endpointom a Graylog používateľa s minimálnymi potrebnými právami.
