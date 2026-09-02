import asyncio

from graylog_mcp.audit import AuditStore


def run(coro):
    return asyncio.run(coro)


def test_store_encrypts_tokens_redacts_payloads_and_scopes_audit(tmp_path):
    async def scenario():
        store = AuditStore(
            tmp_path / "audit.db",
            retention_days=30,
            max_rows=1000,
            max_payload_chars=10_000,
            secret_encryption_key="test-master-key-with-32-characters",
        )
        await store.open()
        try:
            server = await store.add_server("prod", "https://graylog.example.com", "graylog-secret")
            raw_token = (await (await store.db.execute(
                "SELECT api_token FROM graylog_servers WHERE id=?", (server["id"],)
            )).fetchone())[0]
            assert raw_token.startswith("enc:v1:")
            assert (await store.get_server(server["id"]))["api_token"] == "graylog-secret"

            first = await store.add_agent("first", server["id"])
            second = await store.add_agent("second", server["id"])
            first_context = await store.authenticate_agent(first["api_key"])
            second_context = await store.authenticate_agent(second["api_key"])

            await store.record(
                source="graylog",
                operation="POST /api/search/messages",
                request={"authorization": "Bearer secret", "nested": {"api_token": "secret"}},
                response={"ok": True},
                error="Authorization: Bearer another-secret; password=do-not-store",
                agent_id=first_context["agent_id"],
            )
            await store.record(
                source="graylog",
                operation="POST /api/search/messages",
                request={"query": "source:second"},
                response={"ok": True},
                agent_id=second_context["agent_id"],
            )

            first_rows = await store.recent(agent_id=first_context["agent_id"])
            assert len(first_rows) == 1
            assert "Bearer secret" not in first_rows[0]["request_json"]
            assert first_rows[0]["request_json"].count("[REDACTED]") == 2
            assert "another-secret" not in first_rows[0]["error"]
            assert "do-not-store" not in first_rows[0]["error"]
            assert await store.count_recent(agent_id=second_context["agent_id"]) == 1

            await store.db.execute(
                "UPDATE audit_log SET operation=? WHERE id=?",
                ("updatedoperation", first_rows[0]["id"]),
            )
            await store.db.commit()
            updated = await store.recent(search="updatedoperation", agent_id=first_context["agent_id"])
            assert [item["operation"] for item in updated] == ["updatedoperation"]
        finally:
            await store.close()

    run(scenario())


def test_store_enables_foreign_keys_and_migrates_plaintext_tokens(tmp_path):
    async def scenario():
        database_path = tmp_path / "migration.db"
        plain = AuditStore(database_path, 30, 1000, 10_000)
        await plain.open()
        server = await plain.add_server("legacy", "https://graylog.example.com", "plaintext-token")
        await plain.close()

        encrypted = AuditStore(
            database_path, 30, 1000, 10_000,
            secret_encryption_key="migration-master-key-with-32-characters",
        )
        await encrypted.open()
        try:
            raw_token = (await (await encrypted.db.execute(
                "SELECT api_token FROM graylog_servers WHERE id=?", (server["id"],)
            )).fetchone())[0]
            assert raw_token.startswith("enc:v1:")
            assert (await encrypted.get_server(server["id"]))["api_token"] == "plaintext-token"
            assert len(await encrypted.list_servers()) == 1
            foreign_keys = (await (await encrypted.db.execute("PRAGMA foreign_keys")).fetchone())[0]
            assert foreign_keys == 1
        finally:
            await encrypted.close()

    run(scenario())
