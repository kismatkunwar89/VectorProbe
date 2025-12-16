from utils.query_builder import build_searchsploit_query


def test_dnsmasq_includes_version():
    query = build_searchsploit_query('domain', 'dnsmasq 2.90 2.90')
    assert query == 'dnsmasq 2.90'


def test_windows_rpc_tokens():
    query = build_searchsploit_query('msrpc', 'Microsoft Windows RPC')
    assert query == 'microsoft windows rpc msrpc'


def test_service_label_fallback_when_no_fingerprint():
    query = build_searchsploit_query('ms-wbt-server', None)
    assert query == 'ms-wbt-server'
