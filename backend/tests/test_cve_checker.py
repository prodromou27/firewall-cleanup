from app.analysis import cve_checker as C


class _Query:
    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return None


class _DB:
    def query(self, *args, **kwargs):
        return _Query()

    def add(self, *args, **kwargs):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


def test_checkpoint_cve_lookup_falls_back_to_keyword_when_exact_cpe_is_empty(monkeypatch):
    def fake_cpe(cpe, key=None):
        return []

    def fake_keyword(query, vendor, os_version, key=None):
        if query == "Check Point Quantum Security Gateway":
            assert vendor == "CheckPoint"
            assert os_version == "R81.20"
            return [{
                "cve_id": "CVE-2099-0001",
                "description": "Check Point Quantum Security Gateway advisory",
                "cvss_score": 8.8,
                "cvss_severity": "HIGH",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
                "cpe": f"keyword:{query}",
                "match_source": "keyword",
            }]
        return []

    monkeypatch.setattr(C, "_query_nvd", fake_cpe)
    monkeypatch.setattr(C, "_query_nvd_keyword", fake_keyword)

    result = C.get_device_cves("dev-1", "CheckPoint", "R81.20", _DB(), force_refresh=True)

    assert result["cves"][0]["cve_id"] == "CVE-2099-0001"
    assert result["lookup_method"] == "cpe+keyword"
    assert result["error"] is None


def test_checkpoint_management_api_version_is_not_cve_queryable(monkeypatch):
    called = {"cpe": False, "keyword": False}

    def fake_cpe(cpe, key=None):
        called["cpe"] = True
        return []

    def fake_keyword(query, vendor, os_version, key=None):
        called["keyword"] = True
        return []

    monkeypatch.setattr(C, "_query_nvd", fake_cpe)
    monkeypatch.setattr(C, "_query_nvd_keyword", fake_keyword)

    result = C.get_device_cves("dev-1", "CheckPoint", "API 2.0.1", _DB(), force_refresh=True)

    assert result["cves"] == []
    assert result["cpe"] is None
    assert "Cannot map OS version" in result["error"]
    assert called == {"cpe": False, "keyword": False}


def test_keyword_filter_requires_matching_version_or_train():
    matching = {
        "cve": {"descriptions": [{"lang": "en", "value": "Affects Check Point R81.20 gateways."}]}
    }
    unrelated = {
        "cve": {"descriptions": [{"lang": "en", "value": "Affects Check Point R80.40 gateways."}]}
    }

    assert C._keyword_vuln_matches_version(matching, "CheckPoint", "R81.20") is True
    assert C._keyword_vuln_matches_version(unrelated, "CheckPoint", "R81.20") is False
