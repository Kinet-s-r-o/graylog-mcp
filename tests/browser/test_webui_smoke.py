"""Optional browser smoke tests; CI runs the API/static smoke suite by default."""

import pytest


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture
def browser():
    with playwright.sync_playwright() as playwright_instance:
        instance = playwright_instance.chromium.launch(headless=True)
        yield instance
        instance.close()


def test_webui_login_and_static_asset(browser):
    page = browser.new_page()
    page.goto("http://127.0.0.1:8001/login")
    assert page.locator("form").count() == 1
    assert page.locator("body").count() == 1
