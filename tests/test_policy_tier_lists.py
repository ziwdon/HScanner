from hscanner.policy.loader import load_default_policy

EXISTING_PRIORITY_EXT = {
    ".sh", ".bash", ".zsh", ".py", ".pyc", ".pyd", ".rpy", ".rpym", ".rpyc",
    ".rpymc", ".rpyb", ".rpa", ".pl", ".rb", ".js", ".jar",
    ".so", ".bin", ".appimage", ".deb", ".rpm", ".run", ".exe", ".dll", ".msi",
    ".scr", ".bat", ".cmd", ".ps1", ".com", ".vbs", ".wsf", ".lnk",
}
EXISTING_HASH_ONLY_EXT = {
    ".pdf", ".docx", ".xlsx", ".mp4", ".mkv", ".png", ".jpg", ".jpeg", ".ogg",
    ".wav", ".svg", ".ttf", ".otf", ".ttc",
    ".pak", ".vpk", ".bundle", ".asset", ".ucas", ".utoc",
}
HIGH_EXT = {
    ".exe", ".dll", ".so", ".bin", ".appimage", ".deb", ".rpm", ".msi", ".run",
    ".scr", ".com", ".lnk",
    ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".vbs", ".wsf",
}
MEDIUM_EXT = {
    ".py", ".pyc", ".pyd", ".rpy", ".rpym", ".rpyc", ".rpymc", ".rpyb", ".rpa",
    ".pl", ".rb", ".js", ".jar",
}
NEW_HASH_ONLY_EXT = {
    ".json", ".xml", ".csv", ".tsv", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".lock", ".map", ".html", ".htm", ".css",
    ".sql", ".graphql", ".proto",
}


def test_every_existing_priority_extension_stays_priority():
    policy = load_default_policy()
    high = {e.lower() for e in policy["buckets"]["upload_candidate"]["high_extensions"]}
    medium = {e.lower() for e in policy["buckets"]["upload_candidate"]["medium_extensions"]}
    actual_priority = high | medium
    assert EXISTING_PRIORITY_EXT <= actual_priority


def test_priority_extensions_are_split_into_high_and_medium_only():
    policy = load_default_policy()
    high = {e.lower() for e in policy["buckets"]["upload_candidate"]["high_extensions"]}
    medium = {e.lower() for e in policy["buckets"]["upload_candidate"]["medium_extensions"]}
    assert high | medium == EXISTING_PRIORITY_EXT
    assert high & medium == set()


def test_high_set_contains_only_os_shell_runnable():
    policy = load_default_policy()
    high = {e.lower() for e in policy["buckets"]["upload_candidate"]["high_extensions"]}
    assert high == HIGH_EXT


def test_medium_set_contains_only_runtime_required():
    policy = load_default_policy()
    medium = {e.lower() for e in policy["buckets"]["upload_candidate"]["medium_extensions"]}
    assert medium == MEDIUM_EXT


def test_legacy_extensions_key_is_absent():
    policy = load_default_policy()
    assert "extensions" not in policy["buckets"]["upload_candidate"]


def test_hash_only_keeps_existing_entries():
    policy = load_default_policy()
    actual = {e.lower() for e in policy["buckets"]["hash_only"]["extensions"]}
    assert EXISTING_HASH_ONLY_EXT <= actual


def test_hash_only_gains_new_data_config_markup_entries():
    policy = load_default_policy()
    actual = {e.lower() for e in policy["buckets"]["hash_only"]["extensions"]}
    assert NEW_HASH_ONLY_EXT <= actual


def test_hash_only_extension_lists_are_disjoint_from_priority():
    policy = load_default_policy()
    actual_hash = {e.lower() for e in policy["buckets"]["hash_only"]["extensions"]}
    high = {e.lower() for e in policy["buckets"]["upload_candidate"]["high_extensions"]}
    medium = {e.lower() for e in policy["buckets"]["upload_candidate"]["medium_extensions"]}
    assert (actual_hash & (high | medium)) == set()