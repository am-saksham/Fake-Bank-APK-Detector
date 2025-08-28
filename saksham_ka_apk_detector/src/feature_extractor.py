import re, math
from typing import Dict, Any
from androguard.misc import AnalyzeAPK
from .utils.rules import (
    DANGEROUS_PERMISSIONS, SUSPICIOUS_API_KEYWORDS, SUSPICIOUS_URL_KEYWORDS
)
from .utils.certs import sha256_fingerprint_der

URL_REGEX = re.compile(rb'(https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+)')

def shannon_entropy(b: bytes) -> float:
    if not b: return 0.0
    freq = {}
    for x in b: freq[x] = freq.get(x, 0)+1
    ln = len(b)
    H = 0.0
    for c in freq.values():
        p = c/ln
        H -= p*math.log2(p)
    return H

