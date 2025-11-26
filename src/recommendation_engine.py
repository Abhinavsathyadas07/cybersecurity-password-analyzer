"""Security Recommendations Engine Module

Provides actionable security recommendations based on analysis results.
"""
from typing import List

class RecommendationEngine:
    def generate(self, analysis: dict) -> List[str]:
        feedback = analysis.get('feedback', [])
        if not feedback:
            feedback.append("Consider using a password manager and enable two-factor authentication.")
        return feedback
