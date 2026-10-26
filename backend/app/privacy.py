"""Hide secrets (passwords, tokens, card numbers) in request bodies and paths."""
import json
from urllib.parse import unquote_plus

MASK = "***"

# Field names treated as secret. Compared in lowercase, exact match.
SECRET_NAMES = {
    "password", "passwd", "pwd", "pass", "secret", "token",
    "apikey", "api_key", "card", "cardnumber", "cvv", "cvc",
}


def _is_secret(name):
    return unquote_plus(str(name)).strip().lower() in SECRET_NAMES


def _mask_json(value):
    """Walk a parsed JSON value at any depth and mask secret fields."""
    if isinstance(value, dict):
        return {k: MASK if _is_secret(k) else _mask_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_json(v) for v in value]
    return value


def _mask_form(text):
    """Mask secrets in 'a=1&b=2' text. Keeps the original text if nothing changes."""
    parts = text.split("&")
    changed = False
    for i, part in enumerate(parts):
        if "=" not in part:
            continue
        key, _, _value = part.partition("=")
        if _is_secret(key):
            parts[i] = f"{key}={MASK}"
            changed = True
    return "&".join(parts) if changed else text


def mask_secrets(text):
    """Mask secrets in a request body (JSON or form). Anything else is returned unchanged."""
    if not text:
        return text
    if text.lstrip()[:1] in ("{", "["):
        try:
            data = json.loads(text)
        except ValueError:
            return text                      # looks like JSON but is not valid
        masked = _mask_json(data)
        if masked == data:
            return text                      # nothing secret: keep the exact original text
        return json.dumps(masked, ensure_ascii=False, separators=(",", ":"))
    return _mask_form(text)


def mask_path(path):
    """Mask secrets in the query string of a path such as '/login?pwd=x'."""
    if not path or "?" not in path:
        return path
    base, query = path.split("?", 1)
    return base + "?" + _mask_form(query)