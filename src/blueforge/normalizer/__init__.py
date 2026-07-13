"""Turns raw log dicts into the common `Event` schema."""

from blueforge.normalizer.normalize import normalize, normalize_many

__all__ = ["normalize", "normalize_many"]
