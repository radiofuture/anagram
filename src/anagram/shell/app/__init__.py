"""The Anagram app: one process on the computer of a member.

`anagram app run` (`AppRuntime`) runs the local UI server, the index helper,
and the background tasks. A launcher (`anagram open`) asks the running app for
a one-time link and opens the browser. The OS starts the app at login
(`anagram.shell.app.autostart`).

Modules:

- `runtime`: `AppRuntime`.
- `lock`: one app for each data directory.
- `logs`: the app log, with paths and exception text removed.
- `control`: the runtime file, one-time open tokens, the health and control routes.
- `launcher`: `open_app`.
- `autostart`: the login service of each operating system.
- `cli`: the commands `app`, `open`, `open-url`.

This package file imports nothing, so that `anagram.shell.ui.server` can import
`anagram.shell.app.control` with no import cycle.
"""
