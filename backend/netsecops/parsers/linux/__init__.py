"""Parsers for AAA services running on ordinary Linux hosts (FR-AAA-04)."""

from netsecops.parsers.linux.freeradius import FreeRadiusParser
from netsecops.parsers.linux.tacplus import TacPlusParser

__all__ = ["FreeRadiusParser", "TacPlusParser"]
