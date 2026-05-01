"""
label_logger.py
---------------
Registra timestamps precisos de cada ataque em /labels/attack_log.jsonl
Formato JSONL (uma entrada por linha) — fácil de cruzar com o pcap depois.

Uso:
    from label_logger import LabelLogger
    log = LabelLogger()
    with log.attack("port_scan", target="172.30.0.11"):
        ...  # executa o ataque
"""

import json
import time
import os
from contextlib import contextmanager
from datetime import datetime, timezone

LABEL_FILE = os.environ.get("LABEL_FILE", "/labels/attack_log.jsonl")


class LabelLogger:
    def __init__(self, path: str = LABEL_FILE):
        self.path = path
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def _write(self, entry: dict):
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    @contextmanager
    def attack(self, name: str, **meta):
        """
        Context manager que grava início e fim do ataque.
        Qualquer metadado extra (target, tool, intensity) é salvo junto.

        Exemplo de linha gerada:
        {"attack": "port_scan", "start_ts": 1700000000.123, "end_ts": 1700000005.456,
         "start_iso": "2024-...", "end_iso": "2024-...", "target": "172.30.0.11"}
        """
        entry = {
            "attack": name,
            "start_ts": time.time(),
            "start_iso": datetime.now(timezone.utc).isoformat(),
            **meta,
        }
        print(f"[LABEL] START  {name}  {entry['start_iso']}")
        try:
            yield entry
        finally:
            entry["end_ts"] = time.time()
            entry["end_iso"] = datetime.now(timezone.utc).isoformat()
            entry["duration_s"] = round(entry["end_ts"] - entry["start_ts"], 3)
            self._write(entry)
            print(f"[LABEL] END    {name}  ({entry['duration_s']}s)")
