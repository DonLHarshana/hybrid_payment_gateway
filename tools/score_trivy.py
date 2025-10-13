# tools/score_trivy.py
import json, csv, argparse, os, glob

# ---------- helpers ----------
def _normalize_rel(path_str: str, du_root: str) -> str:
    """Normalize any path (absolute/relative, with/without file://) to
    a clean path *relative to the DU root* (e.g., 'configs/.env')."""
    if not path_str:
        return ""
    # strip file:// if present
    if path_str.startswith("file://"):
        path_str = path_str[len("file://"):]
    # anchor relative paths to DU root
    if not os.path.isabs(path_str):
        path_str = os.path.join(du_root, path_str)
    # normalize and make relative to DU
    rel = os.path.relpath(os.path.normpath(path_str), du_root)
    # unify separators for cross-platform consistency
    return rel.replace("\\", "/")

def load_gt(du_root: str):
    """Read ground-truth planted secret locations."""
    gt_file = os.path.join(du_root, "ground_truth", "secrets.csv")
    if not os.path.exists(gt_file):
        return []
    out = []
    with open(gt_file, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            rel = _normalize_rel(row.get("file", ""), du_root)
            try:
                line = int(row.get("line", 0))
            except Exception:
                line = 0
            out.append({"file": rel, "line": line})
    return out

def load_sarif(sarif_path: str, du_root: str):
    """Extract file + line + level from SARIF results."""
    with open(sarif_path, encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for run in data.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations", [])
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            uri  = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {}) or {}
            line = int(region.get("startLine", 0) or 0)
            level = (res.get("level", "") or "").lower()  # error/warning/note/none
            rel = _normalize_rel(uri, du_root)
            out.append({"file": rel, "line": line, "level": level})
    return out

def match(gt, findings, tol=5):
    """Greedy 1:1 matching with ±tol line tolerance."""
    used = [False] * len(gt)
    tp, fp = 0, 0
    for f in findings:
        hit = False
        for i, g in enumerate(gt):
            if used[i]:
                continue
            if f["file"] == g["file"] and abs(f["line"] - g["line"]) <= tol:
                used[i] = True
                tp += 1
                hit = True
                break
        if not hit:
            fp += 1
    fn = used.count(False)
    return tp, fp, fn

def sev_buckets(findings):
    """Count findings by SARIF level (map to high/medium/low)."""
    s = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        lvl = f.get("level", "")
        if lvl == "error":
            s["high"] += 1
        elif lvl == "warning":
            s["medium"] += 1
        else:  # "note", "none", "" -> low
            s["low"] += 1
    return s

def risk_score(sev):
    total = sev["high"] + sev["medium"] + sev["low"]
    if total == 0:
        return 0.0
    # weighted 0..1 : high=3, medium=2, low=1, normalized by 3*total
    return round((3*sev["high"] + 2*sev["medium"] + sev["low"]) / (3*total), 3)

# ---------- main ----------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets_root", default="datasets")
    ap.add_argument("--artifacts_root", default="artifacts")
    ap.add_argument("--tolerance", type=int, default=5,
                    help="line-number tolerance for matching (default: 5)")
    args = ap.parse_args()

    os.makedirs(args.artifacts_root, exist_ok=True)

    rows = [
        "payment_set_id,n_gt,TP,FP,FN,precision,recall,f1,high,medium,low,trivy_risk_score"
    ]

    for du in sorted(glob.glob(os.path.join(args.datasets_root, "payment_set_*"))):
        du_id = os.path.basename(du)           # e.g., payment_set_0001
        set_num = du_id.split("_")[-1]         # e.g., 0001
        sarif = os.path.join(args.artifacts_root, f"{set_num}_trivy.sarif")
        if not os.path.exists(sarif):
            print(f"[WARN] missing SARIF for {du_id}; skipping")
            continue

        gt = load_gt(du)
        findings = load_sarif(sarif, du)
        tp, fp, fn = match(gt, findings, tol=args.tolerance)
        sev = sev_buckets(findings)

        prec = round(tp / (tp + fp), 3) if (tp + fp) else 0.0
        rec  = round(tp / (tp + fn), 3) if (tp + fn) else 0.0
        f1   = round((2*prec*rec) / (prec + rec), 3) if (prec + rec) else 0.0
        risk = risk_score(sev)

        rows.append(
            f"{du_id},{len(gt)},{tp},{fp},{fn},{prec},{rec},{f1},{sev['high']},{sev['medium']},{sev['low']},{risk}"
        )

    out = os.path.join(args.artifacts_root, "trivy_metrics.csv")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(rows))
    print(f"[OK] wrote {out}")
