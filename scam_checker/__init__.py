"""scam-checker: flag common Indian scam patterns in SMS / WhatsApp messages."""

from .detector import Category, Match, Result, analyze

__all__ = ["Category", "Match", "Result", "analyze"]
__version__ = "0.1.0"
