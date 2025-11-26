"""Unit tests for hash comparator"""
def test_hash_comparator():
    from src.hash_comparator import HashComparator
    hc = HashComparator()
    bcrypt_result = hc.hash_password("demoPass!@#", "bcrypt")
    assert bcrypt_result['algorithm'] == 'bcrypt'
    assert bcrypt_result['hash']
    assert 'hash_length' in bcrypt_result
