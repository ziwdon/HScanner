from enum import StrEnum


class ErrorCode(StrEnum):
    PERMISSION_DENIED = "permission_denied"
    FILE_VANISHED = "file_vanished"
    UNSUPPORTED_FILE_TYPE = "unsupported_file_type"
    HASH_FAILED = "hash_failed"
    ENGINE_MISSING_KEY = "engine_missing_key"
    ENGINE_AUTH_FAILED = "engine_auth_failed"
    ENGINE_RATE_LIMITED = "engine_rate_limited"
    ENGINE_QUOTA_EXHAUSTED = "engine_quota_exhausted"
    ENGINE_NETWORK_ERROR = "engine_network_error"
    ENGINE_SERVER_ERROR = "engine_server_error"
    ENGINE_CLIENT_ERROR = "engine_client_error"
    UPLOAD_FAILED = "upload_failed"
    ANALYSIS_TIMEOUT = "analysis_timeout"


class HScannerError(Exception):
    def __init__(
        self, code: ErrorCode, message: str, retry_after: float | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after
