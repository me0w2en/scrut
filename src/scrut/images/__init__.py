"""Forensic image readers for Scrut DFIR CLI.

Provides direct access to files inside forensic images (E01, raw, VMDK)
without requiring OS-level mounting.
"""

from scrut.images.base import ImageReader, open_image

__all__ = ["ImageReader", "open_image"]
