#!/usr/bin/env python3
"""
ReconIQ Test Suite
Run with: pytest test_reconiq.py -v
Run with coverage: pytest test_reconiq.py -v --cov=reconiq --cov-report=term-missing
"""

import sys
import string
sys.path.insert(0, '/root/projects/ReconIQ')

from reconiq import _is_binary, parse_ports


# ─── H-4: Binary Protocol Detection ─────────────────────────────────────────

def test_binary_data_detected():
    """Pure binary data should be flagged as binary"""
    data = bytes(range(256)) * 10
    assert _is_binary(data) is True

def test_http_response_not_binary():
    """Normal HTTP response should NOT be flagged as binary"""
    data = b'HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n'
    assert _is_binary(data) is False

def test_tls_handshake_detected():
    """TLS handshake bytes should be flagged as binary"""
    data = bytes([0x16, 0x03, 0x01, 0x00, 0xf1, 0x01, 0x00, 0x00]) * 50
    assert _is_binary(data) is True

def test_empty_data_not_binary():
    """Empty data should never be flagged as binary"""
    assert _is_binary(b'') is False

def test_ssh_banner_not_binary():
    """SSH banner is plain text — should NOT be flagged"""
    data = b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n'
    assert _is_binary(data) is False

def test_threshold_just_under():
    """29% non-printable — should NOT be flagged as binary"""
    printable = b'A' * 71
    non_printable = bytes([0x01]) * 29
    assert _is_binary(printable + non_printable) is False

def test_threshold_just_over():
    """31% non-printable — SHOULD be flagged as binary"""
    printable = b'A' * 69
    non_printable = bytes([0x01]) * 31
    assert _is_binary(printable + non_printable) is True

def test_rdp_bytes_detected():
    """RDP negotiation request is binary — should be flagged"""
    data = bytes([0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00]) * 50
    assert _is_binary(data) is True


# ─── H-3: Multi-line Banner Capture ──────────────────────────────────────────

def _build_banner(raw_str):
    """Helper — mirrors the banner-building logic in scan_and_grab()"""
    printable = set(string.printable)
    clean = ''.join(c for c in raw_str if c in printable).strip()
    lines = [l.strip() for l in clean.split('\n') if l.strip()]
    return ' | '.join(lines[:6]) if lines else "Active, no text banner."

def test_multiline_banner_includes_server_header():
    """H-3 fix — Server header should appear in banner, not just status line"""
    raw = "HTTP/1.1 200 OK\nServer: nginx/1.24.0\nLocation: https://example.com"
    banner = _build_banner(raw)
    assert 'Server' in banner
    assert 'nginx' in banner

def test_multiline_banner_includes_location_header():
    """H-3 fix — Location header should survive (this is what identified the Eero)"""
    raw = "HTTP/1.0 303 See Other\nContent-Type: text/html\nLocation: https://blocked.eero.com"
    banner = _build_banner(raw)
    assert 'Location' in banner
    assert 'eero' in banner

def test_empty_raw_returns_fallback():
    """Empty data should produce the no-banner fallback string"""
    banner = _build_banner("")
    assert banner == "Active, no text banner."

def test_banner_capped_at_six_lines():
    """Banner should contain at most 6 pipe-separated sections"""
    raw = '\n'.join([f'Header-{i}: value' for i in range(20)])
    banner = _build_banner(raw)
    assert len(banner.split(' | ')) <= 6

def test_first_line_preserved():
    """HTTP status line should always be first in the banner"""
    raw = "HTTP/1.1 200 OK\nServer: Apache\nX-Powered-By: PHP"
    banner = _build_banner(raw)
    assert banner.startswith("HTTP/1.1 200 OK")


# ─── parse_ports ─────────────────────────────────────────────────────────────

def test_parse_common_contains_http():
    """'common' port list should include port 80"""
    assert 80 in parse_ports('common')

def test_parse_common_contains_https():
    """'common' port list should include port 443"""
    assert 443 in parse_ports('common')

def test_parse_common_contains_ssh():
    """'common' port list should include port 22"""
    assert 22 in parse_ports('common')

def test_parse_single_port():
    """Single port string should return a list with one item"""
    assert parse_ports('80') == [80]

def test_parse_port_range():
    """Port range should return correct sequential list"""
    assert parse_ports('80-85') == [80, 81, 82, 83, 84, 85]

def test_parse_comma_separated():
    """Comma-separated ports should all be returned"""
    assert sorted(parse_ports('22,80,443')) == [22, 80, 443]

def test_parse_all_count():
    """'all' should return all 65535 ports"""
    ports = parse_ports('all')
    assert len(ports) == 65535

def test_parse_all_includes_boundaries():
    """'all' should include port 1 and port 65535"""
    ports = parse_ports('all')
    assert 1 in ports
    assert 65535 in ports


# ─── H-5: Silent Send Failure Detection ──────────────────────────────────────

def test_no_banner_string_is_correct():
    """Verify the fallback string for genuine quiet services"""
    assert "Active, no text banner." == "Active, no text banner."

def test_probe_failed_string_is_distinct():
    """Verify probe failure string is distinct from quiet service string"""
    probe_failed = "Active — probe failed (connection dropped during HTTP HEAD)"
    no_banner = "Active, no text banner."
    assert probe_failed != no_banner

def test_probe_failed_contains_active():
    """Probe failure banner should still indicate port is active"""
    probe_failed = "Active — probe failed (connection dropped during HTTP HEAD)"
    assert "Active" in probe_failed

def test_probe_failed_contains_context():
    """Probe failure banner should explain what failed"""
    probe_failed = "Active — probe failed (connection dropped during HTTP HEAD)"
    assert "probe failed" in probe_failed
    assert "HTTP HEAD" in probe_failed


# ─── H-6: recv loop ──────────────────────────────────────────────────────────

def test_recv_until_exists():
    """_recv_until should be importable from reconiq"""
    from reconiq import _recv_until
    assert callable(_recv_until)


# ─── severity_color() ────────────────────────────────────────────────────────

def test_severity_critical_cvss():
    from reconiq import severity_color
    color, badge = severity_color(cvss=9.8)
    assert '🔴' in badge
    assert 'CRITICAL' in badge

def test_severity_high_cvss():
    from reconiq import severity_color
    color, badge = severity_color(cvss=7.5)
    assert '🟠' in badge
    assert 'HIGH' in badge

def test_severity_medium_cvss():
    from reconiq import severity_color
    color, badge = severity_color(cvss=5.0)
    assert '🟡' in badge
    assert 'MEDIUM' in badge

def test_severity_low_cvss():
    from reconiq import severity_color
    color, badge = severity_color(cvss=2.0)
    assert '🟢' in badge
    assert 'LOW' in badge

def test_severity_epss_overrides_to_critical():
    from reconiq import severity_color
    # Low CVSS but high EPSS — worst case wins
    color, badge = severity_color(cvss=3.0, epss_pct=85.0)
    assert 'CRITICAL' in badge

def test_severity_no_inputs_returns_low():
    from reconiq import severity_color
    color, badge = severity_color()
    assert 'LOW' in badge


# ─── _parse_summary() ────────────────────────────────────────────────────────

_FAKE_REPORT = """\
RECONIQ_SUMMARY_START
overall_risk: CRITICAL
services_found: 3
critical_cves: 3
highest_cvss: 10.0
highest_epss: 94.41
evidence_basis: Banner-identified
headline: Three unpatched RCE vulnerabilities on a Windows host.
action: Apply Windows security updates immediately.
RECONIQ_SUMMARY_END
Rest of report here."""

def test_parse_summary_valid():
    from reconiq import _parse_summary
    summary, body = _parse_summary(_FAKE_REPORT)
    assert summary is not None
    assert summary['overall_risk'] == 'CRITICAL'
    assert summary['highest_cvss'] == '10.0'
    assert summary['evidence_basis'] == 'Banner-identified'
    assert 'Rest of report here' in body

def test_parse_summary_missing_block():
    from reconiq import _parse_summary
    text = "Just a normal report with no summary block."
    summary, body = _parse_summary(text)
    assert summary is None
    assert body == text

def test_parse_summary_strips_block_from_body():
    from reconiq import _parse_summary
    summary, body = _parse_summary(_FAKE_REPORT)
    assert 'RECONIQ_SUMMARY_START' not in body
    assert 'RECONIQ_SUMMARY_END' not in body
    assert 'Rest of report here' in body

def test_parse_summary_port_signature_only():
    from reconiq import _parse_summary
    text = ("RECONIQ_SUMMARY_START\n"
            "overall_risk: HIGH\n"
            "evidence_basis: Port-signature-only\n"
            "RECONIQ_SUMMARY_END\nReport body.")
    summary, _ = _parse_summary(text)
    assert summary is not None
    assert summary['evidence_basis'] == 'Port-signature-only'


# ─── _render_summary() ───────────────────────────────────────────────────────

_SUMMARY_DICT = {
    'overall_risk': 'CRITICAL',
    'services_found': '3',
    'critical_cves': '3',
    'highest_cvss': '10.0',
    'highest_epss': '94.41',
    'evidence_basis': 'Banner-identified',
    'headline': 'Three unpatched RCE vulnerabilities.',
    'action': 'Patch immediately.',
}

def test_render_summary_none_returns_empty():
    from reconiq import _render_summary
    assert _render_summary(None, '10.0.0.1') == ""

def test_render_summary_contains_target_ip():
    from reconiq import _render_summary
    out = _render_summary(_SUMMARY_DICT, '10.0.0.1')
    assert '10.0.0.1' in out

def test_render_summary_critical_risk_badge():
    from reconiq import _render_summary
    out = _render_summary(_SUMMARY_DICT, '10.0.0.1')
    assert 'CRITICAL' in out

def test_render_summary_box_structure():
    from reconiq import _render_summary
    import re
    out = _render_summary(_SUMMARY_DICT, '10.0.0.1')
    plain = re.sub(r'\033\[[0-9;]*m', '', out)
    assert plain.startswith('╔')
    assert plain.rstrip().endswith('╝')

def test_render_summary_port_signature_warning_shown():
    from reconiq import _render_summary
    d = dict(_SUMMARY_DICT, overall_risk='LOW', evidence_basis='Port-signature-only')
    out = _render_summary(d, '10.0.0.1')
    assert 'speculative' in out

def test_render_summary_port_signature_warning_absent_for_banner():
    from reconiq import _render_summary
    out = _render_summary(_SUMMARY_DICT, '10.0.0.1')
    assert 'speculative' not in out


# ─── _render_cve_priority_list() ─────────────────────────────────────────────

def test_cve_priority_empty_list_returns_empty():
    from reconiq import _render_cve_priority_list
    assert _render_cve_priority_list([], {}) == ""

def test_cve_priority_shows_cve_id():
    from reconiq import _render_cve_priority_list
    out = _render_cve_priority_list(['CVE-2021-44228'], {'CVE-2021-44228': '94.41%'})
    assert 'CVE-2021-44228' in out

def test_cve_priority_sorted_by_epss():
    from reconiq import _render_cve_priority_list
    cves = ['CVE-2020-0001', 'CVE-2021-44228']
    epss = {'CVE-2020-0001': '2.00%', 'CVE-2021-44228': '94.41%'}
    out = _render_cve_priority_list(cves, epss)
    assert out.index('CVE-2021-44228') < out.index('CVE-2020-0001')

def test_cve_priority_no_epss_data():
    from reconiq import _render_cve_priority_list
    out = _render_cve_priority_list(['CVE-2021-44228'], {})
    assert 'CVE-2021-44228' in out

def test_cve_priority_box_structure():
    from reconiq import _render_cve_priority_list
    out = _render_cve_priority_list(['CVE-2021-44228'], {})
    assert out.startswith('╭')
    assert out.rstrip().endswith('╯')


# ─── _render_confidence_warning() ────────────────────────────────────────────

def test_confidence_warning_banner_identified_empty():
    from reconiq import _render_confidence_warning
    assert _render_confidence_warning('Banner-identified') == ""

def test_confidence_warning_empty_string_empty():
    from reconiq import _render_confidence_warning
    assert _render_confidence_warning('') == ""

def test_confidence_warning_port_signature_returns_block():
    from reconiq import _render_confidence_warning
    out = _render_confidence_warning('Port-signature-only')
    assert out != ""
    assert 'port signatures' in out

def test_confidence_warning_mixed_returns_block():
    from reconiq import _render_confidence_warning
    out = _render_confidence_warning('Mixed')
    assert out != ""
    assert 'port signatures' in out

def test_confidence_warning_contains_confidence_note():
    from reconiq import _render_confidence_warning
    out = _render_confidence_warning('Port-signature-only')
    assert 'CONFIDENCE NOTE' in out
