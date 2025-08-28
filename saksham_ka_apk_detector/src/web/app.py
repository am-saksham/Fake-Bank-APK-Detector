import streamlit as st
import tempfile, sys
from pathlib import Path

# Ensure 'src' is on sys.path when running `streamlit run src/web/app.py`
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from src.analyze_apk import analyze  # now it will import correctly

st.set_page_config(page_title="Fake Banking APK Detector", layout="wide")
st.title("🔍 Fake Banking APK Detector")

st.write("Upload an APK to analyze. The tool runs static analysis and heuristic scoring.")

apk_file = st.file_uploader("Choose an APK", type=["apk"])

if apk_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        tmp.write(apk_file.read())
        tmp_path = tmp.name

    with st.spinner("Analyzing..."):
        try:
            result = analyze(tmp_path)
        except Exception as e:
            st.error(f"Analysis failed: {e}")
            result = None

    if result:
        left, right = st.columns([1,2], gap="large")
        with left:
            st.subheader("Verdict")
            st.metric("Verdict", result["verdict"], delta=f"Risk: {result['risk_score']} / 100")

            st.subheader("Reasons")
            for r in result["reasons"]:
                st.write("• " + r)

        with right:
            f = result["features"]
            st.subheader("Key Metadata")
            st.write(f"**Package:** {f.get('package')}")
            st.write(f"**App Label:** {f.get('label')}")
            st.write(f"**Version:** {f.get('version_name')} ({f.get('version_code')})")

            st.subheader("Permissions")
            st.code("\n".join(f.get("permissions_list", [])) or "(none)")

            st.subheader("URLs (truncated)")
            urls = f.get("urls_list", [])
            if urls:
                for u in urls[:50]:
                    st.write("- " + u)
                if len(urls) > 50:
                    st.write(f"... and {len(urls)-50} more")
            else:
                st.write("(none)")

            st.subheader("Certificate SHA-256")
            certs = f.get("cert_sha256_list", [])
            if certs:
                for c in certs: st.code(c)
            else:
                st.write("(none)")
else:
    st.info("Upload an APK to begin.")