"""Cybersecurity & Password Security Analyzer

A comprehensive security assessment tool for password analysis and vulnerability detection.
"""

__version__ = "1.0.0"
__author__ = "Abhinav T S"
__email__ = "abhinavsathyadas@gmail.com"

from .password_analyzer import PasswordAnalyzer
from .hash_comparator import HashComparator
from .vulnerability_scanner import VulnerabilityScanner
from .recommendation_engine import RecommendationEngine

__all__ = [
    'PasswordAnalyzer',
    'HashComparator',
    'VulnerabilityScanner',
    'RecommendationEngine'
]