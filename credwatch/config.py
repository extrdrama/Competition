"""配置加载：环境变量（.env）、渠道配置、规则目录。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
DEFAULT_SOURCES_FILE = PROJECT_ROOT / "config" / "sources.yaml"
DEFAULT_RULES_DIR = PROJECT_ROOT / "config" / "rules"
DEFAULT_SCORING_WEIGHTS = PROJECT_ROOT / "config" / "scoring_weights.json"


def load_dotenv(path: Path | str | None = None) -> dict[str, str]:
    """极简 .env 解析器，避免引入额外依赖。已存在的环境变量优先。"""
    env_path = Path(path) if path else PROJECT_ROOT / ".env"
    loaded: dict[str, str] = {}
    if not env_path.exists():
        return loaded
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        loaded[key] = value
        os.environ.setdefault(key, value)
    return loaded


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


@dataclass
class Settings:
    """运行时配置聚合体。"""

    db_path: Path = field(default_factory=lambda: PROJECT_ROOT / "data" / "credwatch.db")
    hmac_salt: str = ""
    enable_validation: bool = False
    validate_timeout: int = 8
    validate_rate_limit: int = 20
    github_tokens: list[str] = field(default_factory=list)
    gitee_token: str = ""
    gitlab_token: str = ""
    gitlab_base_url: str = "https://gitlab.com"
    weibo_token: str = ""
    sources_file: Path = DEFAULT_SOURCES_FILE
    rules_dir: Path = DEFAULT_RULES_DIR
    scoring_weights_file: Path = DEFAULT_SCORING_WEIGHTS
    user_agent: str = "CredWatch/1.0 (+security-research; defensive-leak-detection)"

    @classmethod
    def load(cls, dotenv_path: Path | str | None = None) -> "Settings":
        load_dotenv(dotenv_path)
        settings = cls()
        settings.db_path = Path(os.getenv("CREDWATCH_DB") or settings.db_path)
        settings.hmac_salt = os.getenv("CREDWATCH_HMAC_SALT", "")
        settings.enable_validation = _bool_env("CREDWATCH_ENABLE_VALIDATION", False)
        settings.validate_timeout = _int_env("CREDWATCH_VALIDATE_TIMEOUT", 8)
        settings.validate_rate_limit = _int_env("CREDWATCH_VALIDATE_RATE_LIMIT", 20)
        settings.github_tokens = [
            t.strip() for t in (os.getenv("GITHUB_TOKENS") or "").split(",") if t.strip()
        ]
        settings.gitee_token = os.getenv("GITEE_TOKEN", "")
        settings.gitlab_token = os.getenv("GITLAB_TOKEN", "")
        settings.gitlab_base_url = os.getenv("GITLAB_BASE_URL", settings.gitlab_base_url)
        settings.weibo_token = os.getenv("WEIBO_ACCESS_TOKEN", "")
        return settings

    def ensure_dirs(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        (PROJECT_ROOT / "output").mkdir(parents=True, exist_ok=True)


def load_sources_config(path: Path | str | None = None) -> dict[str, Any]:
    """读取渠道配置 config/sources.yaml。"""
    target = Path(path) if path else DEFAULT_SOURCES_FILE
    if not target.exists():
        return {"sources": {}}
    return yaml.safe_load(target.read_text(encoding="utf-8")) or {"sources": {}}


def list_project_files() -> dict[str, list[str]]:
    """列出各规则文件与文档，供 CLI 的 sources / rules 子命令使用。"""
    rules = sorted(p.name for p in DEFAULT_RULES_DIR.glob("*.y*ml"))
    docs = sorted(p.name for p in (PROJECT_ROOT / "docs").glob("*.md"))
    return {"rules": rules, "docs": docs}
