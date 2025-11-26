"""API Integration Examples

Shows how to integrate the analyzer into your own applications.
"""

from src.password_analyzer import PasswordAnalyzer
from src.vulnerability_scanner import VulnerabilityScanner
import json


class PasswordValidator:
    """Example: Custom password validator using the analyzer"""
    
    def __init__(self, min_score=60):
        self.analyzer = PasswordAnalyzer()
        self.scanner = VulnerabilityScanner()
        self.min_score = min_score
    
    def validate(self, password: str) -> dict:
        """Validate password and return detailed results"""
        analysis = self.analyzer.analyze(password)
        vuln_scan = self.scanner.scan(password)
        
        is_valid = (
            analysis['score'] >= self.min_score and
            not vuln_scan['is_common'] and
            analysis['length'] >= 12
        )
        
        return {
            'valid': is_valid,
            'score': analysis['score'],
            'strength': analysis['strength_level'],
            'issues': self._get_issues(analysis, vuln_scan),
            'recommendations': analysis['feedback']
        }
    
    def _get_issues(self, analysis, vuln_scan):
        """Identify specific issues with the password"""
        issues = []
        
        if analysis['length'] < 12:
            issues.append("Password too short (minimum 12 characters)")
        
        if analysis['score'] < self.min_score:
            issues.append(f"Password score below threshold ({analysis['score']}/{self.min_score})")
        
        if vuln_scan['is_common']:
            issues.append("Password found in common password database")
        
        char_analysis = analysis['character_analysis']
        if char_analysis['uppercase'] == 0:
            issues.append("Missing uppercase letters")
        if char_analysis['lowercase'] == 0:
            issues.append("Missing lowercase letters")
        if char_analysis['digits'] == 0:
            issues.append("Missing digits")
        if char_analysis['special'] == 0:
            issues.append("Missing special characters")
        
        return issues


def example_web_api_response():
    """Example: Format for web API response"""
    print("\nExample: Web API Response Format\n")
    
    validator = PasswordValidator(min_score=60)
    password = "TestPassword123!"
    
    result = validator.validate(password)
    
    # Format as JSON response
    api_response = {
        'status': 'success',
        'data': {
            'password_valid': result['valid'],
            'security_score': result['score'],
            'strength_level': result['strength'],
            'issues': result['issues'],
            'recommendations': result['recommendations'][:3]
        }
    }
    
    print(json.dumps(api_response, indent=2))


def example_registration_flow():
    """Example: User registration password validation"""
    print("\nExample: Registration Flow Validation\n")
    
    validator = PasswordValidator(min_score=60)
    
    # Simulate user registration attempts
    attempts = [
        "weak",
        "Password123",
        "MySecure!Pass@2024"
    ]
    
    for attempt in attempts:
        print(f"Attempting password: '{attempt}'")
        result = validator.validate(attempt)
        
        if result['valid']:
            print("  ✓ Password accepted!")
            print(f"  Strength: {result['strength']} (Score: {result['score']})")
        else:
            print("  ✗ Password rejected!")
            print("  Issues:")
            for issue in result['issues']:
                print(f"    - {issue}")
        print()


def example_security_audit():
    """Example: Security audit of existing passwords"""
    print("\nExample: Security Audit\n")
    
    analyzer = PasswordAnalyzer()
    scanner = VulnerabilityScanner()
    
    # Simulated password database
    user_passwords = [
        {"user_id": 1, "username": "alice", "password": "alice123"},
        {"user_id": 2, "username": "bob", "password": "SecureP@ss2024!"},
        {"user_id": 3, "username": "charlie", "password": "password"},
    ]
    
    print("Auditing user passwords:\n")
    
    vulnerabilities = []
    
    for user in user_passwords:
        analysis = analyzer.analyze(user['password'])
        vuln = scanner.scan(user['password'])
        
        if vuln['is_common'] or analysis['score'] < 50:
            vulnerabilities.append({
                'user_id': user['user_id'],
                'username': user['username'],
                'score': analysis['score'],
                'is_common': vuln['is_common'],
                'action': 'Force password reset'
            })
    
    print("Vulnerabilities found:")
    for vuln in vulnerabilities:
        print(f"  User: {vuln['username']} (ID: {vuln['user_id']})")
        print(f"    Score: {vuln['score']}/100")
        print(f"    Common password: {vuln['is_common']}")
        print(f"    Action: {vuln['action']}")
        print()


if __name__ == "__main__":
    print("=" * 70)
    print(" " * 20 + "API INTEGRATION EXAMPLES")
    print("=" * 70)
    
    example_web_api_response()
    example_registration_flow()
    example_security_audit()
    
    print("\n" + "=" * 70)
    print(" " * 25 + "EXAMPLES COMPLETE")
    print("=" * 70 + "\n")
