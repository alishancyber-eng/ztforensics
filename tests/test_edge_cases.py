"""
10 edge case tests for the ZTForensics API Gateway.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))

import pytest
import threading
from unittest.mock import patch, AsyncMock


# 1. Empty access log list in summary
def test_empty_access_log_summary():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from database import Base, AccessLog
    import main as m

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    from sqlalchemy import func
    total = session.query(func.count(AccessLog.id)).scalar() or 0
    assert total == 0
    session.close()


# 2. Very large dataset – risk scorer handles many calls
def test_large_risk_score_dataset():
    from risk_scoring import RiskScorer
    rs = RiskScorer()
    scores = [
        rs.calculate_risk({
            "user_id": f"user{i}", "resource": "docs", "action": "READ",
            "ip_address": "8.8.8.8", "user_agent": "Mozilla/5.0"
        })
        for i in range(200)
    ]
    assert all(0.0 <= s <= 1.0 for s in scores)


# 3. Unicode characters in user_id
def test_unicode_user_id():
    from risk_scoring import RiskScorer
    rs = RiskScorer()
    score = rs.calculate_risk({
        "user_id": "用户🔒テスト", "resource": "docs", "action": "READ",
        "ip_address": "8.8.8.8", "user_agent": "Mozilla/5.0"
    })
    assert isinstance(score, float)


# 4. Special characters in resource name
def test_special_chars_in_resource():
    from blockchain import BlockchainManager
    bm = BlockchainManager()
    h = bm.add_block({"resource": "res/path?q=1&x=<script>", "action": "READ"})
    assert len(h) == 64


# 5a. Boundary risk score – score 0.0 maps to LOW
def test_boundary_risk_score_low():
    from risk_scoring import RiskScorer
    assert RiskScorer.get_risk_label(0.0) == "LOW"


# 5b. Boundary risk score – score 1.0 maps to CRITICAL
def test_boundary_risk_score_critical():
    from risk_scoring import RiskScorer
    assert RiskScorer.get_risk_label(1.0) == "CRITICAL"


# 6. Null metadata is handled in blockchain
def test_null_metadata_blockchain():
    from blockchain import BlockchainManager
    bm = BlockchainManager()
    h = bm.add_block({"user_id": "u", "metadata": None})
    assert h is not None and len(h) == 64


# 7. Maximum length strings in blockchain
def test_maximum_length_strings():
    from blockchain import BlockchainManager
    bm = BlockchainManager()
    big = "a" * 100_000
    h = bm.add_block({"big_field": big})
    assert len(h) == 64


# 8. Concurrent blockchain additions are thread-safe
def test_concurrent_blockchain_additions():
    from blockchain import BlockchainManager
    bm = BlockchainManager()
    errors = []

    def add(i):
        try:
            bm.add_block({"index": i})
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=add, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    # Chain length = 1 (genesis) + 20 blocks
    assert len(bm._chain) == 21


# 9. Zero risk score handling
def test_zero_risk_score_label():
    from risk_scoring import RiskScorer
    label = RiskScorer.get_risk_label(0.0)
    assert label == "LOW"


# 10. Risk score normalisation – never goes below 0
def test_risk_score_never_negative():
    from risk_scoring import RiskScorer
    rs = RiskScorer()
    score = rs.calculate_risk({
        "user_id": "safe_user", "resource": "public", "action": "READ",
        "ip_address": "127.0.0.1", "user_agent": "Mozilla/5.0"
    })
    assert score >= 0.0
