from flask import request
from flask_limiter import Limiter


def _ip():
    return (request.headers.get("X-Real-IP") or request.remote_addr or "0.0.0.0")


limiter = Limiter(key_func=_ip, default_limits=[])
