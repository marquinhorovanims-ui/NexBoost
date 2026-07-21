"""Algoritmo de chaves do NexBoost (idêntico ao do aplicativo)."""
import hashlib
import secrets


_SALT = "NexBoost/2026/f4a1c9"
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sem 0/O/1/I (legibilidade)
_PREFIX = "NEXB"
_BLOCK = 5


def _checksum(payload: str) -> str:
    """Bloco de verificação derivado do payload + salt."""
    digest = hashlib.sha256(f"{_SALT}:{payload}".encode()).digest()
    return "".join(_ALPHABET[b % len(_ALPHABET)] for b in digest[:_BLOCK])


def normalize(key: str) -> str:
    """Remove espaços, uniformiza maiúsculas e reagrupa com hifens.

    O prefixo ``NEXB`` tem 4 caracteres e os demais blocos têm 5 — o
    reagrupamento respeita isso (bug clássico: fatiar tudo em 5 quebrava
    todas as chaves).
    """
    cleaned = "".join(ch for ch in (key or "").upper() if ch.isalnum())
    if cleaned.startswith(_PREFIX):
        rest = cleaned[len(_PREFIX):]
        parts = [_PREFIX] + [rest[i:i + _BLOCK]
                             for i in range(0, len(rest), _BLOCK)]
    else:
        parts = [cleaned[i:i + _BLOCK]
                 for i in range(0, len(cleaned), _BLOCK)]
    return "-".join(part for part in parts if part)


def is_valid(key: str) -> bool:
    """Valida o formato e o checksum da chave."""
    normalized = normalize(key)
    parts = normalized.split("-")
    if len(parts) != 4 or parts[0] != _PREFIX:
        return False
    if any(len(part) != _BLOCK for part in parts[1:]):
        return False
    if any(ch not in _ALPHABET for part in parts[1:] for ch in part):
        return False
    payload = f"{parts[1]}-{parts[2]}"
    return _checksum(payload) == parts[3]


def generate_key() -> str:
    """Gera uma chave válida (uso do distribuidor)."""
    block_a = "".join(secrets.choice(_ALPHABET) for _ in range(_BLOCK))
    block_b = "".join(secrets.choice(_ALPHABET) for _ in range(_BLOCK))
    return f"{_PREFIX}-{block_a}-{block_b}-{_checksum(f'{block_a}-{block_b}')}"


