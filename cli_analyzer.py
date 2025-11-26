"""Command-line Password Analyzer
Analyze password strength and get recommendations from your terminal."""
import sys
from src.password_analyzer import PasswordAnalyzer
from src.vulnerability_scanner import VulnerabilityScanner
from src.recommendation_engine import RecommendationEngine

def main():
    pa = PasswordAnalyzer()
    vs = VulnerabilityScanner()
    re = RecommendationEngine()
    
    if len(sys.argv) < 2:
        print("Usage: python cli_analyzer.py <password>")
        return
    password = sys.argv[1]
    analysis = pa.analyze(password)
    vscan = vs.scan(password)
    recs = re.generate(analysis)
    print("\n[Password Strength]")
    print(f"Level: {analysis['strength_level']}")
    print(f"Score: {analysis['score']}")
    print(f"Entropy: {analysis['entropy']} bits")
    print(f"Crack Time: {analysis['crack_time']}")
    print("\n[Character Details]")
    for k,v in analysis['character_analysis'].items():
        print(f"{k.capitalize()}: {v}")
    print("\n[Feedback]")
    for fb in recs:
        print(f"- {fb}")
    print("\n[Vulnerability Scan]")
    print(f"Common Password: {vscan['is_common']}")
    print(f"Recommendation: {vscan['recommendation']}")
main() if __name__ == "__main__" else None
