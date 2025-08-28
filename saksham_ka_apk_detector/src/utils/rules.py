DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.CALL_PHONE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}

SUSPICIOUS_API_KEYWORDS = {
    "sendTextMessage",     
    "DexClassLoader",      
    "Class.forName",       
    "loadUrl",             
    "AccessibilityService"
}

SUSPICIOUS_URL_KEYWORDS = [
    "http://", ".top", ".xyz", "/wp-", "/php?"
]

WEIGHTS = {
    "unknown_cert": 35,
    "uses_sms": 15,
    "uses_accessibility": 15,
    "uses_overlay": 10,
    "requests_install_packages": 15,
    "suspicious_api": 10,
    "suspicious_url": 10,
    "entropy_bonus": 5,
}