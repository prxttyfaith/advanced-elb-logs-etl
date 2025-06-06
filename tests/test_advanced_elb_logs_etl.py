import sys
import os
import pytest

# Ensure the parent directory is in sys.path for module resolution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 
print(f"sys.path: {sys.path}")

from advanced_elb_logs_etl import (
    parse_log_entry,
    to_int,
    to_float
)

# Parse log entry tests

def test_to_int_valid():
    assert to_int("42") == 42

def test_to_int_invalid():
    assert to_int("-") is None
    assert to_int("") is None
    assert to_int(None) is None

def test_to_float_valid():
    assert to_float("3.14") == 3.14

def test_to_float_invalid():
    assert to_float("-") is None
    assert to_float("") is None
    assert to_float(None) is None

def test_parse_log_entry_minimal():
    # sample edited log line
    log_line = (
        'h2 2025-05-26T23:55:02.179979Z app/erank-app/88dfa9dc536560af 3.135.238.214:60827 '
        '172.31.37.43:80 0.001 0.303 0.000 200 200 74 1013 '
        '"POST https://beta.erank.com:443/api/browser-ext-user HTTP/2.0" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/137.0.0.0 Safari/537.36" TLS_AES_128_GCM_SHA256 TLSv1.3 '
        'arn:aws:elasticloadbalancing:us-west-2:848357551741:targetgroup/erank-app-v3-production/902b52047b6f4e28 '
        '"Root=1-6834ff55-4f9107ec4dcec228218b6176" "beta.erank.com" "session-reused" 1 '
        '2025-05-26T23:55:01.875000Z "waf,forward" "-" "-" "172.31.37.43:80" "200" "-" "-" TID_b087994534c4ac4abc0185b56b077382'
    )
    row = parse_log_entry(log_line, "dummy.log.gz")
    assert row is not None
    assert row["client_ip"] == "3.135.238.214"
    assert row["http_method"] == "POST"
    assert row["hostname"] == "beta.erank.com"
