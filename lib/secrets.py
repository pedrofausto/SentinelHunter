"""Minimal secret-string wrapper to prevent accidental credential exposure in logs."""


class _SecretStr:
    """Wraps a sensitive string so repr/str never leak the value."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def get(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "**REDACTED**"

    def __str__(self) -> str:
        return "**REDACTED**"

    def __bool__(self) -> bool:
        return bool(self._value)
