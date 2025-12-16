"""Helpers for building searchsploit queries from Nmap fingerprints."""

from __future__ import annotations

import re
from typing import List, Optional

TOKEN_PATTERN = re.compile(r'[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*')
VERSION_PATTERN = re.compile(r'\d+(?:\.\d+)+')

# Generic terms that do not help Searchsploit find specific software.
# Merged from GENERIC_TERMS and STOP_WORDS for single source of truth.
SEARCHSPLOIT_FILTER_TERMS = {
    'client', 'default', 'domain', 'http', 'https', 'open', 'port',
    'protocol', 'server', 'service', 'services', 'ssl', 'tls',
    'tcp', 'udp', 'unknown'
}


def _tokenize(value: str) -> List[str]:
    """Return normalized tokens extracted from raw fingerprint/service text."""
    if not value:
        return []

    tokens: List[str] = []
    for token in TOKEN_PATTERN.findall(value):
        normalized = token.strip('-_.').lower()
        if not normalized:
            continue
        tokens.append(normalized)
    return tokens


def build_searchsploit_query(
    service_label: Optional[str],
    fingerprint: Optional[str]
) -> str:
    """Create a Searchsploit query from service metadata without per-service rules."""
    ordered_tokens: List[str] = []
    seen = set()

    for source in (fingerprint, service_label):
        for token in _tokenize(source or ''):
            if token in seen:
                continue
            if len(token) <= 2:
                continue
            if token in SEARCHSPLOIT_FILTER_TERMS:
                continue
            if VERSION_PATTERN.fullmatch(token):
                continue
            ordered_tokens.append(token)
            seen.add(token)

    if not ordered_tokens:
        if service_label:
            fallback = service_label.strip().lower()
            return fallback
        return ''

    version = None
    if fingerprint:
        version_match = VERSION_PATTERN.search(fingerprint)
        if version_match:
            version = version_match.group(0)

    query_terms = ordered_tokens[:4]
    if version:
        query_terms.append(version)

    return " ".join(query_terms).strip()
