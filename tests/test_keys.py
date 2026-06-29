from hscanner.keys import resolve_api_key


def test_env_key_wins_over_saved_key(monkeypatch) -> None:
    monkeypatch.setenv("HS_API_KEY_VIRUSTOTAL", "env-key")

    assert resolve_api_key("virustotal", saved_key_loader=lambda: "saved-key") == "env-key"


def test_saved_key_used_when_env_missing(monkeypatch) -> None:
    monkeypatch.delenv("HS_API_KEY_VIRUSTOTAL", raising=False)

    assert resolve_api_key("virustotal", saved_key_loader=lambda: "saved-key") == "saved-key"


def test_keys_are_per_engine(monkeypatch):
    from hscanner import keys

    store = {}

    class FakeKeyring:
        def get_password(self, s, u): return store.get((s, u))
        def set_password(self, s, u, p): store[(s, u)] = p
        def delete_password(self, s, u): store.pop((s, u), None)

    kr = FakeKeyring()
    keys.save_api_key("virustotal", "VTKEY", keyring_module=kr)
    keys.save_api_key("metadefender", "MDKEY", keyring_module=kr)
    assert keys.load_saved_api_key("virustotal", keyring_module=kr) == "VTKEY"
    assert keys.load_saved_api_key("metadefender", keyring_module=kr) == "MDKEY"
    monkeypatch.setenv("HS_API_KEY_METADEFENDER", "ENVMD")
    assert keys.resolve_api_key(
        "metadefender", lambda: keys.load_saved_api_key("metadefender", keyring_module=kr)
    ) == "ENVMD"
