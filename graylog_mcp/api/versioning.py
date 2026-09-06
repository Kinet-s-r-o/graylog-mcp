"""API compatibility contract shared by all transport adapters."""

API_VERSION = "1"
API_VERSION_HEADER = "X-API-Version"
DEPRECATION_HEADER = "Deprecation"


def version_headers() -> dict[str, str]:
    return {API_VERSION_HEADER: API_VERSION}
