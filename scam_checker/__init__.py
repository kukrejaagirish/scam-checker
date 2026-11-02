"""scam-checker: flag common Indian scam patterns in SMS / WhatsApp messages."""

from .detector import Category, Match, Result, analyze, normalize

__all__ = ["Category", "Match", "Result", "analyze", "normalize"]
__version__ = "0.2.0"
