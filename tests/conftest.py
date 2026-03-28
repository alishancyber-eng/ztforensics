import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))

# Set SQLite URL before any database import to avoid psycopg2 dependency
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base, AccessLog

TEST_DATABASE_URL = "sqlite:///:memory:"

@pytest.fixture(scope="session")
def test_engine():
    from sqlalchemy.pool import StaticPool
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session(test_engine):
    TestSessionLocal = sessionmaker(bind=test_engine)
    session = TestSessionLocal()
    yield session
    session.rollback()
    session.close()

@pytest.fixture
def sample_access_request():
    return {
        "user_id": "user123",
        "resource": "document_store",
        "action": "READ",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0",
        "metadata": {}
    }

@pytest.fixture
def sample_log_entry():
    return {
        "user_id": "user123",
        "resource": "document_store",
        "action": "READ",
        "decision": "allow",
        "risk_score": 0.2,
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0"
    }
