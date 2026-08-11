"""
Abstract Base Parser — interface yang harus diimplement oleh setiap parser source.

Cara nambah source baru:
  1. Bikin class baru extend BaseParser
  2. Implement parse() → yield dict per baris
  3. Daftarin di normalizer.py + main.py
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator


class BaseParser(ABC):
    """Parser dasar: baca file log baris-per-baris, yield dict terstruktur."""

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.source_type: str = "unknown"
        self.skipped: int = 0      # baris corrupt
        self.parsed: int = 0       # baris sukses
        self.total_lines: int = 0  # estimasi total baris

    @abstractmethod
    def parse(self) -> Iterator[dict]:
        """
        Baca file, parse tiap baris, yield dict event mentah.
        Baris corrupt di-skip (self.skipped +1).
        Harus generator (memory-efficient).
        """
        ...

    def _count_lines(self) -> int:
        """Estimasi total baris file (buat progress bar)."""
        count = 0
        with open(self.filepath, "rb") as f:
            for _ in f:
                count += 1
        return count

    def progress_message(self) -> str:
        return f"[...] {self.source_type} | {self.filepath.name}: {self.parsed:,} diparse"
