from omega.auth import issue_token, verify_token


def test_token_is_rejected_at_exact_expiry_boundary():
    token = issue_token("k" * 32, "operator:test", ["chat.read"], ttl=1, now=100)
    assert verify_token("k" * 32, token, now=100.999) is not None
    assert verify_token("k" * 32, token, now=101) is None


def test_token_is_rejected_after_expiry():
    token = issue_token("k" * 32, "operator:test", ["chat.read"], ttl=1, now=100)
    assert verify_token("k" * 32, token, now=102) is None


def test_token_is_rejected_with_wrong_key():
    token = issue_token("k" * 32, "operator:test", ["chat.read"], ttl=60, now=100)
    assert verify_token("x" * 32, token, now=101) is None
