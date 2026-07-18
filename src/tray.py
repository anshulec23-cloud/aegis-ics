import os
import sys
import logging
from typing import Any, Callable, Optional
import pystray
from PIL import Image, ImageDraw
logger = logging.getLogger(__name__)

def _resource_path(relative_path: str) -> str:
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)

def create_default_icon() -> Image.Image:
    size = 64
    image = Image.new('RGBA', (size, size), '#1a1a1a')
    draw = ImageDraw.Draw(image)
    padding = 8
    draw.ellipse([padding, padding, size - padding, size - padding], fill='#34d399')
    return image

class AegisTray:

    def __init__(self, window: Any, on_quit_callback: Callable[[], None], on_check_updates: Callable[[], None]) -> None:
        self.window: Any = window
        self._on_quit_callback: Callable[[], None] = on_quit_callback
        self._on_check_updates: Callable[[], None] = on_check_updates
        icon_image = self._load_icon()
        menu = pystray.Menu(pystray.MenuItem('Open Dashboard', self._show_window, default=True), pystray.Menu.SEPARATOR, pystray.MenuItem('Check for Updates', self._check_updates), pystray.Menu.SEPARATOR, pystray.MenuItem('Quit Aegis ICS', self._quit))
        self.icon: pystray.Icon = pystray.Icon(name='AegisICS', icon=icon_image, title='Aegis ICS — Industrial Security v2.2.3', menu=menu)
        logger.info('AegisTray initialised.')

    @staticmethod
    def _load_icon() -> Image.Image:
        icon_path = _resource_path(os.path.join('static', 'icon.png'))
        if os.path.isfile(icon_path):
            logger.debug('Loading tray icon from %s', icon_path)
            return Image.open(icon_path)
        logger.warning('Icon file not found at %s; using generated fallback icon.', icon_path)
        return create_default_icon()

    def _show_window(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        if self.window is None:
            logger.warning('Cannot show window: window reference is None.')
            return
        try:
            self.window.show()
            self.window.restore()
            logger.debug('Window shown and restored.')
        except Exception:
            logger.exception('Failed to show/restore the window.')

    def _check_updates(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        logger.info('Check for Updates requested from tray menu.')
        self._on_check_updates()

    def _quit(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        logger.info('Quit requested from tray menu.')
        self.icon.stop()
        self._on_quit_callback()

    def run(self) -> None:
        logger.info('Starting tray icon event loop.')
        self.icon.run()

    def stop(self) -> None:
        logger.info('Stopping tray icon.')
        self.icon.stop()