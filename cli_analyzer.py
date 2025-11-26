#!/usr/bin/env python3
"""Command-line Password Security Analyzer

Analyze password strength and get security recommendations from your terminal.

Usage:
    python cli_analyzer.py <password>
    python cli_analyzer.py --help
    python cli_analyzer.py --interactive
"""

import sys
import argparse
from src.password_analyzer import PasswordAnalyzer
from src.hash_comparator import HashComparator
from src.vulnerability_scanner import VulnerabilityScanner
from src.recommendation_engine import RecommendationEngine

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''


def print_header():
    """Print application header."""
    if COLORS_AVAILABLE:
        print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("="*70)
    print(" " * 10 + "🔐 CYBERSECURITY & PASSWORD SECURITY ANALYZER")
    print(" " * 15 + "Command-Line Interface v1.0")
    print("="*70)
    if COLORS_AVAILABLE:
        print(f"{Style.RESET_ALL}")


def print_section(title):
    """Print section header."""
    if COLORS_AVAILABLE:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}{title}{Style.RESET_ALL}")
    else:
        print(f"\n{title}")
    print("-" * 70)


def get_color_for_strength(strength_level):
    """Get color based on strength level."""
    if not COLORS_AVAILABLE:
        return ''
    
    colors = {
        'Very Weak': Fore.RED,
        'Weak': Fore.RED,
        'Moderate': Fore.YELLOW,
        'Strong': Fore.GREEN,
        'Very Strong': Fore.GREEN
    }
    return colors.get(strength_level, Fore.WHITE)


def analyze_password(password, verbose=False):
    """Analyze password and display results.
    
    Args:
        password: Password to analyze
        verbose: Show detailed analysis
    """
    # Initialize components
    analyzer = PasswordAnalyzer()
    vuln_scanner = VulnerabilityScanner()
    rec_engine = RecommendationEngine()
    
    # Perform analysis
    print("\nAnalyzing password...")
    analysis = analyzer.analyze(password)
    vuln_result = vuln_scanner.scan(password)
    recommendations = rec_engine.generate(analysis)
    
    # Display results
    print_header()
    
    # === PASSWORD STRENGTH ===
    print_section("📊 PASSWORD STRENGTH ANALYSIS")
    
    strength_color = get_color_for_strength(analysis['strength_level'])
    
    print(f"Strength Level:  {strength_color}{Style.BRIGHT}{analysis['strength_level']}{Style.RESET_ALL}")
    print(f"Overall Score:   {analysis['score']}/100")
    print(f"Entropy:         {analysis['entropy']:.2f} bits")
    print(f"Crack Time:      {analysis['crack_time']}")
    print(f"Password Length: {analysis['length']} characters")
    
    # Visual strength bar
    bar_length = 50
    filled = int((analysis['score'] / 100) * bar_length)
    bar = '█' * filled + '░' * (bar_length - filled)
    print(f"\nStrength Bar:    [{bar}] {analysis['score']}%")
    
    # === CHARACTER ANALYSIS ===
    print_section("🔤 CHARACTER COMPOSITION")
    char_analysis = analysis['character_analysis']
    
    print(f"Lowercase:       {char_analysis['lowercase']} characters")
    print(f"Uppercase:       {char_analysis['uppercase']} characters")
    print(f"Digits:          {char_analysis['digits']} characters")
    print(f"Special Chars:   {char_analysis['special']} characters")
    print(f"Unique Chars:    {char_analysis['unique_chars']} out of {analysis['length']}")
    print(f"Repeated Chars:  {char_analysis['repeated_chars']}")
    
    # === PATTERN DETECTION ===
    if verbose:
        print_section("🔍 PATTERN DETECTION")
        patterns = analysis['pattern_analysis']
        
        pattern_found = False
        for pattern_name, detected in patterns.items():
            if detected:
                pattern_found = True
                pattern_display = pattern_name.replace('_', ' ').title()
                print(f"{Fore.RED}⚠️  {pattern_display}{Style.RESET_ALL}")
        
        if not pattern_found:
            print(f"{Fore.GREEN}✅ No common patterns detected{Style.RESET_ALL}")
    
    # === VULNERABILITY SCAN ===
    print_section("🛡️ VULNERABILITY ASSESSMENT")
    
    if vuln_result['is_common']:
        print(f"{Fore.RED}{Style.BRIGHT}🚨 CRITICAL WARNING: This password is in the common password database!{Style.RESET_ALL}")
        print(f"{Fore.RED}   This password is extremely vulnerable to attacks.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}✅ Password not found in common password database{Style.RESET_ALL}")
        print(f"   Checked against {vuln_result['checked_against']:,} known weak passwords")
    
    # === RECOMMENDATIONS ===
    print_section("💡 SECURITY RECOMMENDATIONS")
    
    for i, rec in enumerate(recommendations, 1):
        print(f"{i}. {rec}")
    
    # === ADDITIONAL INFO ===
    if verbose:
        print_section("📝 ADDITIONAL INFORMATION")
        
        if 'zxcvbn_score' in analysis:
            print(f"zxcvbn Score:    {analysis['zxcvbn_score']}/4")
            if 'zxcvbn_feedback' in analysis and analysis['zxcvbn_feedback']:
                zxcvbn_fb = analysis['zxcvbn_feedback']
                if zxcvbn_fb.get('warning'):
                    print(f"Warning:         {zxcvbn_fb['warning']}")
                if zxcvbn_fb.get('suggestions'):
                    print("Suggestions:")
                    for sugg in zxcvbn_fb['suggestions']:
                        print(f"  - {sugg}")
        
        print(f"\nComplexity Score: {analysis['complexity_score']}/100")
    
    print("\n" + "="*70)
    print(f"{Fore.CYAN}Analysis complete. Stay secure!{Style.RESET_ALL}")
    print("="*70 + "\n")


def interactive_mode():
    """Run analyzer in interactive mode."""
    print_header()
    print("\nWelcome to Interactive Mode!")
    print("Type 'quit' or 'exit' to end the session.\n")
    
    while True:
        try:
            password = input(f"{Fore.CYAN}Enter password to analyze (or 'quit'): {Style.RESET_ALL}")
            
            if password.lower() in ['quit', 'exit', 'q']:
                print(f"\n{Fore.YELLOW}Exiting analyzer. Stay secure!{Style.RESET_ALL}\n")
                break
            
            if not password:
                print(f"{Fore.RED}Please enter a password.{Style.RESET_ALL}\n")
                continue
            
            verbose = input(f"{Fore.CYAN}Show detailed analysis? (y/n): {Style.RESET_ALL}").lower().startswith('y')
            
            analyze_password(password, verbose=verbose)
            
            print(f"\n{'-'*70}\n")
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}Interrupted. Exiting...{Style.RESET_ALL}\n")
            break
        except Exception as e:
            print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}\n")


def compare_hashes(password):
    """Compare hash algorithms for a password."""
    print_header()
    print_section("⚙️ HASH ALGORITHM COMPARISON")
    
    comparator = HashComparator()
    results = comparator.compare_all(password, iterations=100)
    
    print(f"\n{'Algorithm':<12} {'Avg Time (ms)':<15} {'Hash Length':<15} {'Security Rating'}")
    print("-" * 80)
    
    for algo, data in results.items():
        if algo not in ['security_analysis', 'recommendations']:
            color = Fore.GREEN if algo == 'bcrypt' else Fore.YELLOW if 'sha' in algo else Fore.RED
            print(f"{color}{data['algorithm'].upper():<12} {data['avg_time_ms']:<15.4f} {data['hash_length']:<15} {data['security_rating']}{Style.RESET_ALL}")
    
    print("\n" + "="*70 + "\n")


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description='Cybersecurity & Password Security Analyzer - CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli_analyzer.py MyPassword123!
  python cli_analyzer.py "Complex!Pass@2024" --verbose
  python cli_analyzer.py --interactive
  python cli_analyzer.py --hash MyPassword123!

For more information, visit:
https://github.com/Abhinavsathyadas07/cybersecurity-password-analyzer
        """
    )
    
    parser.add_argument('password', nargs='?', help='Password to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed analysis')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--hash', action='store_true', help='Compare hash algorithms')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    
    args = parser.parse_args()
    
    try:
        if args.interactive:
            interactive_mode()
        elif args.password:
            if args.hash:
                compare_hashes(args.password)
            else:
                analyze_password(args.password, verbose=args.verbose)
        else:
            parser.print_help()
            sys.exit(1)
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
