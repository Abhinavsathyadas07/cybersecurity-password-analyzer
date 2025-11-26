"""Basic Usage Examples

Demonstrates how to use the Password Security Analyzer programmatically.
"""

from src.password_analyzer import PasswordAnalyzer
from src.hash_comparator import HashComparator
from src.vulnerability_scanner import VulnerabilityScanner
from src.recommendation_engine import RecommendationEngine


def example_1_basic_analysis():
    """Example 1: Basic password analysis"""
    print("\n" + "="*70)
    print("EXAMPLE 1: Basic Password Analysis")
    print("="*70)
    
    analyzer = PasswordAnalyzer()
    password = "MyPassword123!"
    
    results = analyzer.analyze(password)
    
    print(f"\nPassword: {password}")
    print(f"Strength Level: {results['strength_level']}")
    print(f"Score: {results['score']}/100")
    print(f"Entropy: {results['entropy']} bits")
    print(f"Estimated Crack Time: {results['crack_time']}")


def example_2_vulnerability_scan():
    """Example 2: Vulnerability scanning"""
    print("\n" + "="*70)
    print("EXAMPLE 2: Vulnerability Scanning")
    print("="*70)
    
    scanner = VulnerabilityScanner()
    
    passwords_to_test = [
        "password",
        "MySecurePassword2024!",
        "123456",
        "qwerty"
    ]
    
    for pwd in passwords_to_test:
        result = scanner.scan(pwd)
        status = "VULNERABLE" if result['is_common'] else "SAFE"
        print(f"\nPassword: '{pwd}' - Status: {status}")
        print(f"  {result['recommendation']}")


def example_3_hash_comparison():
    """Example 3: Hash algorithm comparison"""
    print("\n" + "="*70)
    print("EXAMPLE 3: Hash Algorithm Comparison")
    print("="*70)
    
    comparator = HashComparator()
    password = "SecurePassword2024!"
    
    print(f"\nComparing hash algorithms for: {password}\n")
    
    algorithms = ['md5', 'sha256', 'bcrypt']
    
    for algo in algorithms:
        result = comparator.hash_password(password, algo)
        print(f"Algorithm: {algo.upper()}")
        print(f"  Time: {result['time_taken']:.4f} ms")
        print(f"  Hash Length: {result['hash_length']}")
        print(f"  Security: {comparator._get_security_rating(algo)}")
        print()


def example_4_complete_workflow():
    """Example 4: Complete security assessment workflow"""
    print("\n" + "="*70)
    print("EXAMPLE 4: Complete Security Assessment")
    print("="*70)
    
    # Initialize all components
    analyzer = PasswordAnalyzer()
    scanner = VulnerabilityScanner()
    rec_engine = RecommendationEngine()
    
    password = "TestPassword123"
    
    print(f"\nAssessing password: {password}\n")
    
    # Step 1: Analyze strength
    analysis = analyzer.analyze(password)
    print("1. Strength Analysis:")
    print(f"   Level: {analysis['strength_level']}")
    print(f"   Score: {analysis['score']}/100")
    
    # Step 2: Scan for vulnerabilities
    vuln_result = scanner.scan(password)
    print("\n2. Vulnerability Scan:")
    print(f"   Common Password: {vuln_result['is_common']}")
    
    # Step 3: Get recommendations
    recommendations = rec_engine.generate(analysis)
    print("\n3. Recommendations:")
    for i, rec in enumerate(recommendations[:3], 1):
        print(f"   {i}. {rec}")


def example_5_batch_analysis():
    """Example 5: Batch password analysis"""
    print("\n" + "="*70)
    print("EXAMPLE 5: Batch Password Analysis")
    print("="*70)
    
    analyzer = PasswordAnalyzer()
    
    passwords = [
        "weak",
        "Password123",
        "MyS3cure!Pass@2024",
        "SuperComplexPassword!2024#Secure"
    ]
    
    print("\nAnalyzing multiple passwords:\n")
    print(f"{'Password':<35} {'Strength':<15} {'Score':<10}")
    print("-" * 60)
    
    for pwd in passwords:
        result = analyzer.analyze(pwd)
        print(f"{pwd:<35} {result['strength_level']:<15} {result['score']:<10}")


def example_6_entropy_comparison():
    """Example 6: Entropy comparison across passwords"""
    print("\n" + "="*70)
    print("EXAMPLE 6: Entropy Comparison")
    print("="*70)
    
    analyzer = PasswordAnalyzer()
    
    test_cases = [
        ("12345678", "8 digits only"),
        ("password", "lowercase only"),
        ("Password", "mixed case"),
        ("Password1", "mixed + digit"),
        ("Password1!", "mixed + digit + special"),
        ("P@ssw0rd!2024", "complex password")
    ]
    
    print("\nEntropy increases with character diversity:\n")
    print(f"{'Password':<20} {'Description':<25} {'Entropy (bits)'}")
    print("-" * 70)
    
    for pwd, desc in test_cases:
        result = analyzer.analyze(pwd)
        print(f"{pwd:<20} {desc:<25} {result['entropy']:.2f}")


def main():
    """Run all examples"""
    print("\n" + "#"*70)
    print("#" + " "*20 + "PASSWORD ANALYZER EXAMPLES" + " "*23 + "#")
    print("#"*70)
    
    examples = [
        example_1_basic_analysis,
        example_2_vulnerability_scan,
        example_3_hash_comparison,
        example_4_complete_workflow,
        example_5_batch_analysis,
        example_6_entropy_comparison
    ]
    
    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"\nError in {example.__name__}: {e}")
    
    print("\n" + "#"*70)
    print("#" + " "*23 + "EXAMPLES COMPLETE" + " "*28 + "#")
    print("#"*70 + "\n")


if __name__ == "__main__":
    main()
