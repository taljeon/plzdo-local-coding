import sys

if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
    raise SystemExit('Use the plzdo-local-code launcher; Python startup requires -I -S -B')

from .cli import main

if __name__ == '__main__':
    raise SystemExit(main())
