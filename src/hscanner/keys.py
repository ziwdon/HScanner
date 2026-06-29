import os
from collections.abc import Callable
from typing import Any

import keyring

SERVICE_NAME = "HScanner"


def _env_var(engine_id: str) -> str:
    return f"HS_API_KEY_{engine_id.upper()}"


def resolve_api_key(engine_id: str, saved_key_loader: Callable[[], str | None]) -> str | None:
    env_key = os.environ.get(_env_var(engine_id))
    if env_key:
        return env_key
    return saved_key_loader()


def load_saved_api_key(engine_id: str, keyring_module: Any = keyring) -> str | None:
    try:
        return keyring_module.get_password(SERVICE_NAME, engine_id)
    except Exception:
        return None


def save_api_key(engine_id: str, api_key: str, keyring_module: Any = keyring) -> bool:
    try:
        keyring_module.set_password(SERVICE_NAME, engine_id, api_key)
        return True
    except Exception:
        return False


def clear_saved_api_key(engine_id: str, keyring_module: Any = keyring) -> bool:
    try:
        keyring_module.delete_password(SERVICE_NAME, engine_id)
        return True
    except Exception:
        return False
