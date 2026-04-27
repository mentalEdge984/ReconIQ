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
