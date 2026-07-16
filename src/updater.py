import logging
import threading
from dataclasses import dataclass, field
from typing import Callable
import requests
logger = logging.getLogger(__name__)

@dataclass
class UpdateInfo:
    available: bool = False
    current_version: str = ''
    latest_version: str = ''
    download_url: str = ''
    release_notes: str = ''
    published_at: str = ''

def _parse_semver(version: str) -> tuple[int, ...]:
    return tuple((int(part) for part in version.split('.')))

def check_for_updates(current_version: str, repo: str) -> UpdateInfo:
    try:
        url = f'https://api.github.com/repos/{repo}/releases/latest'
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        tag_name: str = data.get('tag_name', '')
        html_url: str = data.get('html_url', '')
        body: str = data.get('body', '') or ''
        published_at: str = data.get('published_at', '')
        latest_version = tag_name.lstrip('v')
        current_tuple = _parse_semver(current_version)
        latest_tuple = _parse_semver(latest_version)
        is_available = latest_tuple > current_tuple
        logger.info('Update check complete: current=%s, latest=%s, available=%s', current_version, latest_version, is_available)
        return UpdateInfo(available=is_available, current_version=current_version, latest_version=latest_version, download_url=html_url, release_notes=body, published_at=published_at)
    except Exception:
        logger.error("Failed to check for updates for repo '%s'", repo, exc_info=True)
        return UpdateInfo(available=False, current_version=current_version)

def check_updates_async(current_version: str, repo: str, callback: Callable[[UpdateInfo], None]) -> None:

    def _worker() -> None:
        update_info = check_for_updates(current_version, repo)
        callback(update_info)
    thread = threading.Thread(target=_worker, name='update-checker', daemon=True)
    thread.start()
    logger.debug("Background update check started for repo '%s'", repo)