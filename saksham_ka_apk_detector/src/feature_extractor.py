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
    for x in b: freq[x] = freq.get(x, 0) + 1
    ln = len(b)
    H = 0.0
    for c in freq.values():
        p = c/ln
        H -= p*math.log2(p)
    return H

def extract_features(apk_path: str) -> Dict[str, Any]:
    a, ds, dx = AnalyzeAPK(apk_path)
    apk = a

    package = apk.get_package()
    label = apk.get_app_name() or ""
    version_name = str(apk.get_androidversion_name() or "")
    version_code = str(apk.get_androidversion_code() or "")

    activities = apk.get_activities() or []
    services = apk.get_services() or []
    receivers = apk.get_receivers() or []
    providers = apk.get_providers() or []

    perms = set(apk.get_permissions() or [])
    dangerous_perms = perms.intersection(DANGEROUS_PERMISSIONS)

    # certificates (try v3/v2/v1)
    cert_fps = []
    for getter in ("get_certificates_der_v3","get_certificates_der_v2","get_certificates_der_v1","get_certificates_der"):
        if hasattr(apk, getter):
            for der in getattr(apk, getter)() or []:
                try:
                    cert_fps.append(sha256_fingerprint_der(der))
                except Exception:
                    pass

    # string scan (URLs + entropy)
    urls = set()
    total_strings = 0
    high_entropy = 0
    for d in ds:
        for s in d.get_strings():
            try:
                val = s.get_value()
                b = val.encode(errors="ignore") if isinstance(val, str) else bytes(val)
                total_strings += 1
                for m in URL_REGEX.finditer(b):
                    urls.add(m.group(1).decode("utf-8", errors="ignore"))
                if shannon_entropy(b) > 4.0 and len(b) >= 16:
                    high_entropy += 1
            except Exception:
                continue

    suspicious_url_hits = sum(1 for u in urls if any(k in u for k in SUSPICIOUS_URL_KEYWORDS))

    suspicious_api_hits = 0
    for meth in dx.get_methods():
        try:
            name = meth.get_method().get_name()
            if any(k in name for k in SUSPICIOUS_API_KEYWORDS):
                suspicious_api_hits += 1
        except Exception:
            continue

    uses_sms = int(any(p in perms for p in ["android.permission.SEND_SMS","android.permission.RECEIVE_SMS","android.permission.READ_SMS"]))
    uses_accessibility = int("android.permission.BIND_ACCESSIBILITY_SERVICE" in perms)
    uses_overlay = int("android.permission.SYSTEM_ALERT_WINDOW" in perms)
    requests_install = int("android.permission.REQUEST_INSTALL_PACKAGES" in perms)

    entropy_ratio = (high_entropy/max(total_strings,1))

    return {
        "package": package,
        "label": label,
        "version_name": version_name,
        "version_code": version_code,

        "n_activities": len(activities),
        "n_services": len(services),
        "n_receivers": len(receivers),
        "n_providers": len(providers),

        "n_permissions": len(perms),
        "n_dangerous_permissions": len(dangerous_perms),

        "uses_sms": uses_sms,
        "uses_accessibility": uses_accessibility,
        "uses_overlay": uses_overlay,
        "requests_install_packages": requests_install,

        "n_urls": len(urls),
        "suspicious_url_hits": suspicious_url_hits,
        "suspicious_api_hits": suspicious_api_hits,
        "entropy_ratio": entropy_ratio,

        "cert_sha256_list": cert_fps,
        "permissions_list": sorted(list(perms)),
        "urls_list": sorted(list(urls)),
    }