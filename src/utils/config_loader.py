import yaml
from pathlib import Path

_config = None


def load_config(path: str = "configs/config.yaml") -> dict:
    global _config
    if _config is None:
        config_path = Path(path)
        with open(config_path) as f:
            _config = yaml.safe_load(f)
    return _config
