"""Forensic artifact parsers for Scrut DFIR CLI."""

# Import parsers to register them
from scrut.parsers import (
    amcache,  # noqa: F401
    browser,  # noqa: F401
    evtx,  # noqa: F401
    jumplists,  # noqa: F401
    lnk,  # noqa: F401
    mft,  # noqa: F401
    prefetch,  # noqa: F401
    recyclebin,  # noqa: F401
    registry,  # noqa: F401
    scheduledtasks,  # noqa: F401
    shellbags,  # noqa: F401
    shimcache,  # noqa: F401
    srum,  # noqa: F401
    usnjrnl,  # noqa: F401
)
from scrut.parsers.base import BaseParser, ParserRegistry

__all__ = ["BaseParser", "ParserRegistry"]
