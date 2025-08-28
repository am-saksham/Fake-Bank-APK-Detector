import json, os
from typing import Dict, Any
from .feature_extractor import extract_features
from .utils.rules import WEIGHTS

def heuristic_score(features: Dict[str, Any], trusted_map: Dict[str, list]):
    score, reasons = 0, []

    pkg = features.get("package")
    certs = features.get("cert_sha256_list") or []
    trusted = set(trusted_map.get(pkg, []))
    if not trusted or not any(c in trusted for c in certs):
        score += WEIGHTS["unknown_cert"]
        reasons.append("Certificate not in trusted whitelist")

    if features.get("uses_sms"): 
        score += WEIGHTS["uses_sms"]; reasons.append("Uses SMS permissions")
    if features.get("uses_accessibility"): 
        score += WEIGHTS["uses_accessibility"]; reasons.append("Requests Accessibility Service")
    if features.get("uses_overlay"): 
        score += WEIGHTS["uses_overlay"]; reasons.append("Requests overlay (SYSTEM_ALERT_WINDOW)")
    if features.get("requests_install_packages"): 
        score += WEIGHTS["requests_install_packages"]; reasons.append("Requests INSTALL_PACKAGES")
    if features.get("suspicious_api_hits",0) > 0:
        score += WEIGHTS["suspicious_api"]; reasons.append("Suspicious API references")
    if features.get("suspicious_url_hits",0) > 0:
        score += WEIGHTS["suspicious_url"]; reasons.append("Suspicious URL patterns found")
    if features.get("entropy_ratio",0) > 0.2:
        score += WEIGHTS["entropy_bonus"]; reasons.append("High ratio of high-entropy strings")

    return score, reasons

def analyze(apk_path: str, trusted_json_path: str = "config/trusted_signatures.json"):
    feats = extract_features(apk_path)
    try:
        with open(trusted_json_path, "r") as f:
            trusted_map = json.load(f).get("trusted", {})
    except Exception:
        trusted_map = {}

    h_score, reasons = heuristic_score(feats, trusted_map)

    # verdict thresholds (tuneable)
    if h_score >= 70:
        verdict = "MALICIOUS"
    elif h_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "verdict": verdict,
        "risk_score": h_score,
        "reasons": reasons,
        "features": feats,
    }