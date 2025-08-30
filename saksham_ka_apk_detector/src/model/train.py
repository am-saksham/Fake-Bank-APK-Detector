import argparse, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from joblib import dump

NUMERIC_FEATURES = [
    "n_activities","n_services","n_receivers","n_providers",
    "n_permissions","n_dangerous_permissions",
    "uses_sms","uses_accessibility","uses_overlay","requests_install_packages",
    "n_urls","suspicious_url_hits","suspicious_api_hits","entropy_ratio"
]

def main(args):
    df = pd.read_csv(args.infile)
    X = df[NUMERIC_FEATURES]
    y = df["label"]

    pipe = Pipeline([
        ("scaler", StandardScaler(with_mean=False)),
        ("rf", RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced"))
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=42
    )

    pipe.fit(X_train, y_train)

    preds = pipe.predict(X_test)
    print("✅ Model trained")
    print(classification_report(y_test, preds, digits=4))

    dump(pipe, args.model)
    print(f"✅ Saved model → {args.model}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--infile", default="data/dataset.csv")
    ap.add_argument("--model", default="artifacts/model.joblib")
    args = ap.parse_args()
    main(args)