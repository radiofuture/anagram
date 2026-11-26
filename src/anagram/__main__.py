"""`python -m anagram`: the same as the `anagram` command (the login service uses it)."""

import sys

from anagram.shell.cli.main import main

sys.exit(main())
