import ctypes
import functools
import os
import secrets
import socket
import sys
from typing import Callable, Any
from flask import jsonify, request
APP_VERSION: str = '2.2.2'
'Current application version string.'
GITHUB_REPO: str = 'anshulsc/aegis-ics'
'GitHub repository identifier used for update checks.'

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _, port = s.getsockname()
        return port

def resource_path(relative_path: str) -> str:
    base_path: str = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def require_webview_token(f: Callable[..., Any]) -> Callable[..., Any]:

    @functools.wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if not os.environ.get('AEGIS_DESKTOP_MODE'):
            return f(*args, **kwargs)
        try:
            import webview
        except ImportError:
            return (jsonify({'error': 'Forbidden – webview module unavailable'}), 403)
        token: str | None = request.headers.get('X-PYWEBVIEW-TOKEN')
        if not token or token != webview.token:
            return (jsonify({'error': 'Forbidden – invalid or missing token'}), 403)
        return f(*args, **kwargs)
    return decorated_function

def generate_runtime_secret() -> str:
    return secrets.token_hex(32)

def check_debugger() -> bool:
    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except (AttributeError, OSError):
        return False