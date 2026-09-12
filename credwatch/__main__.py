"""模块入口：支持 `python -m credwatch ...`。"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
