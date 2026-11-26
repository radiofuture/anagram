"""Local web UI: `anagram` (or `anagram ui`) serves it on 127.0.0.1.

See `anagram.shell.ui.server` for the security rules and `anagram.shell.ui.service` for
the screen actions. Static files are in `static/` (no build step, no CDN).
"""

from anagram.shell.ui.errors import UIError
from anagram.shell.ui.service import UIService

__all__ = ["UIError", "UIService"]
