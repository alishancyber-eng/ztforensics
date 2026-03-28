"""
Unit tests for api_gateway/timeline_analyzer.py
"""
import pytest
from timeline_analyzer import group_records_by_period


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record(ts: str, decision: str = "ALLOW", risk: int = 0, idx: int = 1):
    return {
        "id": idx,
        "timestamp": ts,
        "decision": decision,
        "risk_score": risk,
        "user_name": "alice",
        "resource": "/api/docs",
    }


# ---------------------------------------------------------------------------
# Tests: empty / edge cases
# ---------------------------------------------------------------------------

class TestEmptyAndEdgeCases:
    def test_empty_records_returns_empty_list(self):
        assert group_records_by_period([]) == []

    def test_record_with_invalid_timestamp_is_skipped(self):
        records = [_record("not-a-date")]
        result = group_records_by_period(records)
        assert result == []

    def test_single_record_produces_one_bucket(self):
        records = [_record("2026-03-27T10:30:00+00:00")]
        result = group_records_by_period(records)
        assert len(result) == 1
        assert result[0]["total_requests"] == 1


# ---------------------------------------------------------------------------
# Tests: grouping by hour
# ---------------------------------------------------------------------------

class TestGroupByHour:
    def test_same_hour_merged_into_one_bucket(self):
        records = [
            _record("2026-03-27T10:05:00+00:00", idx=1),
            _record("2026-03-27T10:45:00+00:00", idx=2),
        ]
        result = group_records_by_period(records, interval="hour")
        assert len(result) == 1
        assert result[0]["total_requests"] == 2

    def test_different_hours_produce_separate_buckets(self):
        records = [
            _record("2026-03-27T10:00:00+00:00", idx=1),
            _record("2026-03-27T11:00:00+00:00", idx=2),
            _record("2026-03-27T12:00:00+00:00", idx=3),
        ]
        result = group_records_by_period(records, interval="hour")
        assert len(result) == 3

    def test_allow_deny_counts_correct(self):
        records = [
            _record("2026-03-27T10:00:00+00:00", decision="ALLOW", idx=1),
            _record("2026-03-27T10:30:00+00:00", decision="DENY",  idx=2),
            _record("2026-03-27T10:50:00+00:00", decision="ALLOW", idx=3),
        ]
        result = group_records_by_period(records, interval="hour")
        assert len(result) == 1
        bucket = result[0]
        assert bucket["allowed"] == 2
        assert bucket["denied"] == 1
        assert bucket["total_requests"] == 3

    def test_period_key_format_hour(self):
        records = [_record("2026-03-27T15:22:10+00:00")]
        result = group_records_by_period(records, interval="hour")
        assert result[0]["period"] == "2026-03-27 15:00"


# ---------------------------------------------------------------------------
# Tests: grouping by day
# ---------------------------------------------------------------------------

class TestGroupByDay:
    def test_same_day_merged(self):
        records = [
            _record("2026-03-27T08:00:00+00:00", idx=1),
            _record("2026-03-27T20:00:00+00:00", idx=2),
        ]
        result = group_records_by_period(records, interval="day")
        assert len(result) == 1
        assert result[0]["total_requests"] == 2

    def test_different_days_separate_buckets(self):
        records = [
            _record("2026-03-27T10:00:00+00:00", idx=1),
            _record("2026-03-28T10:00:00+00:00", idx=2),
        ]
        result = group_records_by_period(records, interval="day")
        assert len(result) == 2

    def test_period_key_format_day(self):
        records = [_record("2026-03-27T15:00:00+00:00")]
        result = group_records_by_period(records, interval="day")
        assert result[0]["period"] == "2026-03-27"


# ---------------------------------------------------------------------------
# Tests: risk score statistics
# ---------------------------------------------------------------------------

class TestRiskStats:
    def test_avg_risk_score_computed(self):
        records = [
            _record("2026-03-27T10:00:00+00:00", risk=0,   idx=1),
            _record("2026-03-27T10:10:00+00:00", risk=100, idx=2),
        ]
        result = group_records_by_period(records, interval="hour")
        assert result[0]["avg_risk_score"] == 50

    def test_high_risk_events_counted(self):
        records = [
            _record("2026-03-27T10:00:00+00:00", risk=80, idx=1),
            _record("2026-03-27T10:10:00+00:00", risk=20, idx=2),
            _record("2026-03-27T10:20:00+00:00", risk=90, idx=3),
        ]
        result = group_records_by_period(records, interval="hour")
        assert result[0]["high_risk_events"] == 2

    def test_sorted_ascending_by_period(self):
        records = [
            _record("2026-03-27T12:00:00+00:00", idx=1),
            _record("2026-03-27T09:00:00+00:00", idx=2),
            _record("2026-03-27T11:00:00+00:00", idx=3),
        ]
        result = group_records_by_period(records, interval="hour")
        periods = [r["period"] for r in result]
        assert periods == sorted(periods)
