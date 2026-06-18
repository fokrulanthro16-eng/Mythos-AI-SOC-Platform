"""tests/test_featherless_client.py — Unit tests for FeatherlessClient."""

from __future__ import annotations

from unittest.mock import patch

from integrations.featherless_client import FeatherlessClient


def _mock_client() -> FeatherlessClient:
    return FeatherlessClient()  # no FEATHERLESS_API_KEY -> mock_mode=True


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


def test_mock_mode_when_no_api_key():
    client = _mock_client()
    assert client.mock_mode is True


def test_real_mode_when_api_key_set():
    with patch.dict("os.environ", {"FEATHERLESS_API_KEY": "test-key-123"}):
        client = FeatherlessClient()
    assert client.mock_mode is False


def test_base_url_default():
    client = _mock_client()
    assert "featherless" in client.base_url


def test_custom_base_url_from_env():
    with patch.dict("os.environ", {"FEATHERLESS_BASE_URL": "https://custom.api/v2"}):
        client = FeatherlessClient()
    assert client.base_url == "https://custom.api/v2"


# ---------------------------------------------------------------------------
# generate_summary
# ---------------------------------------------------------------------------


def test_generate_summary_returns_string():
    result = _mock_client().generate_summary("APT-SHADOW-VIPER", ["C2:1.2.3.4"])
    assert isinstance(result, str) and len(result) > 0


def test_generate_summary_known_threat_contains_context():
    result = _mock_client().generate_summary("APT-SHADOW-VIPER", [])
    assert "TA505" in result or "containment" in result.lower()


def test_generate_summary_unknown_threat_is_generic():
    result = _mock_client().generate_summary("UNKNOWN-THREAT-XYZ", ["ip:1.1.1.1"])
    assert "UNKNOWN-THREAT-XYZ" in result


def test_generate_summary_includes_ioc_count_for_unknown():
    result = _mock_client().generate_summary("UNKNOWN-XYZ", ["ip:1.1.1.1", "hash:abc"])
    assert "2" in result


# ---------------------------------------------------------------------------
# classify_threat
# ---------------------------------------------------------------------------


def test_classify_threat_returns_dict():
    result = _mock_client().classify_threat(["C2:185.220.101.47"])
    assert isinstance(result, dict)


def test_classify_threat_has_category_key():
    result = _mock_client().classify_threat(["hash:abc123"])
    assert "category" in result


def test_classify_threat_confidence_in_bounds():
    result = _mock_client().classify_threat(["C2:185.220.101.47"])
    assert 0.0 <= result["confidence"] <= 1.0


def test_classify_threat_c2_prefix():
    result = _mock_client().classify_threat(["C2:1.2.3.4"])
    assert result["category"] == "C2_INFRASTRUCTURE"


def test_classify_threat_hash_prefix():
    result = _mock_client().classify_threat(["hash:deadbeef"])
    assert result["category"] == "MALWARE_HASH"


def test_classify_threat_empty_list_returns_unknown():
    result = _mock_client().classify_threat([])
    assert result["category"] == "UNKNOWN"
    assert result["confidence"] == 0.0


def test_classify_threat_unknown_prefix_is_generic():
    result = _mock_client().classify_threat(["xyz:something"])
    assert "category" in result
    assert result["confidence"] >= 0.0


# ---------------------------------------------------------------------------
# actor_analysis
# ---------------------------------------------------------------------------


def test_actor_analysis_returns_dict():
    result = _mock_client().actor_analysis("APT-SHADOW-VIPER")
    assert isinstance(result, dict)


def test_actor_analysis_known_threat_has_profile_key():
    result = _mock_client().actor_analysis("APT-SHADOW-VIPER")
    assert result.get("profile_key") == "TA505"


def test_actor_analysis_known_threat_has_ttps():
    result = _mock_client().actor_analysis("RANSOMWARE-LOCKBIT3")
    assert isinstance(result.get("ttps"), list) and len(result["ttps"]) > 0


def test_actor_analysis_unknown_threat_profile_key_is_none():
    result = _mock_client().actor_analysis("UNKNOWN-THREAT-XYZ")
    assert result.get("profile_key") is None


def test_actor_analysis_has_confidence_key():
    result = _mock_client().actor_analysis("APT-SHADOW-VIPER")
    assert "confidence" in result
    assert 0.0 <= result["confidence"] <= 1.0
