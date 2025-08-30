import argparse, os, pandas as pd
from tqdm import tqdm
from src.feature_extractor import extract_features

NUMERIC_FEATURES = [
    "n_activities","n_services","n_receivers","n_providers",
    "n_permissions","n_dangerous_permissions",
    "uses_sms","uses_accessibility","uses_overlay","requests_install_packages",
    "n_urls","suspicious_url_hits","suspicious_api_hits","entropy_ratio"
]

def process_dir(dir_path, label):
    rows = []
    if not os.path.isdir(dir_path):
        return rows
    for fn in tqdm(os.listdir(dir_path)):
        if not fn.endswith(".apk"):
            continue
        try:
            feats = extract_features(os.path.join(dir_path, fn))
            row = {k: feats.get(k, 0) for k in NUMERIC_FEATURES}
            row["apk_path"] = fn
            row["label"] = label  # 0 = genuine, 1 = fake
            rows.append(row)
        except Exception as e:
            print(f"Failed {fn}: {e}")
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--genuine", default="data/genuine_apks")
    ap.add_argument("--fake", default="data/fake_apks")
    ap.add_argument("--out", default="data/dataset.csv")
    args = ap.parse_args()

    rows = []
    rows += process_dir(args.genuine, 0)
    rows += process_dir(args.fake, 1)

    df = pd.DataFrame(rows)
    df.to_csv(args.out, index=False)
    print(f"✅ Saved {len(df)} rows to {args.out}")

if __name__ == "__main__":
    main()