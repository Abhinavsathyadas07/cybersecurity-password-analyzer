"""Unit tests for password strength analyzer"""
def test_password_analyzer():
    from src.password_analyzer import PasswordAnalyzer
    pa = PasswordAnalyzer()
    results = pa.analyze("Password123!")
    assert results['length'] == 12
    assert results['score'] > 0
    assert 'strength_level' in results
