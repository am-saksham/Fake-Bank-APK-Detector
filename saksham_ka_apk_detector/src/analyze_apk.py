import json, os
from typing import Dict, Any

import pandas as pd
from .feature_extractor import extract_features
from .utils.rules import WEIGHTS
from joblib import load
import numpy as np

NUMERIC_FEATURES = [
    "n_activities","n_services","n_receivers","n_providers",
    "n_permissions","n_dangerous_permissions",
    "uses_sms","uses_accessibility","uses_overlay","requests_install_packages",
    "n_urls","suspicious_url_hits","suspicious_api_hits","entropy_ratio"
]

def load_model(model_path="artifacts/model.joblib"):
    try:
        return load(model_path)
    except:
        return None

def predict_with_model(model, features):
    if model is None:
        return 0.0, -1
    
    x = pd.DataFrame([[features[k] for k in NUMERIC_FEATURES]], columns=NUMERIC_FEATURES)
    
    if hasattr(model, "predict_proba"):
        proba_arr = model.predict_proba(x)[0]
        if len(proba_arr) == 2:  # binary classifier
            proba = proba_arr[1]
            pred = int(proba >= 0.5)
        else:  # only one class present in training
            proba = 0.0
            pred = model.predict(x)[0]
        return float(proba), pred
    else:
        pred = model.predict(x)[0]
        return 1.0 if pred == 1 else 0.0, pred


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

def analyze(apk_path: str, trusted_json_path: str = "config/trusted_signatures.json",  model_path="artifacts/model.joblib"):
    feats = extract_features(apk_path)
    try:
        with open(trusted_json_path, "r") as f:
            trusted_map = json.load(f).get("trusted", {})
    except Exception:
        trusted_map = {}

    h_score, reasons = heuristic_score(feats, trusted_map)

    model = load_model(model_path)
    ml_proba, ml_pred = predict_with_model(model, feats)

    combined = h_score + int(ml_proba * 50)
    # verdict thresholds (tuneable)
    if combined >= 70:
        verdict = "MALICIOUS"
    elif combined >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "verdict": verdict,
        "risk_score": int(combined),
        "heuristic_score": h_score,
        "ml_probability_fake": ml_proba,
        "ml_prediction": ml_pred,
        "reasons": reasons,
        "features": feats,
    }