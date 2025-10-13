import json, csv, argparse, os, glob
from pathlib import Path

def load_gt(du):
    gt = []
    p = Path(du)/"ground_truth"/"secrets.csv"
    if not p.exists(): return gt
    with p.open() as f:
        r = csv.DictReader(f)
        for row in r:
            rel = os.path.relpath(row["file"], du)
            gt.append({"file": rel, "line": int(row["line"])})
    return gt

def load_sarif(sarif_path, du_root):
    with open(sarif_path) as f:
        data = json.load(f)
    out = []
    for run in data.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations", [])
            if not locs: continue
            phys = locs[0].get("physicalLocation", {})
            uri  = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 0)
            level = res.get("level", "")  # error/warning/note
            rel = os.path.relpath(uri, du_root)
            out.append({"file": rel, "line": int(line), "level": level})
    return out

def match(gt, findings, tol=2):
    gt_used = [False]*len(gt)
    tp, fp = 0, 0
    for f in findings:
        hit = False
        for i,g in enumerate(gt):
            if gt_used[i]: continue
            if f["file"] == g["file"] and abs(f["line"] - g["line"]) <= tol:
                gt_used[i] = True; tp += 1; hit = True; break
        if not hit: fp += 1
    fn = gt_used.count(False)
    return tp, fp, fn

def sev(findings):
    s={"high":0,"medium":0,"low":0}
    for f in findings:
        if f["level"]=="error": s["high"]+=1
        elif f["level"]=="warning": s["medium"]+=1
        else: s["low"]+=1
    return s

def risk_score(sv):
    total = sv["high"]+sv["medium"]+sv["low"]
    if total==0: return 0.0
    return round((3*sv["high"]+2*sv["medium"]+sv["low"])/(3*total),3)

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--datasets_root", default="datasets")
    ap.add_argument("--artifacts_root", default="artifacts")
    args=ap.parse_args()

    os.makedirs(args.artifacts_root, exist_ok=True)
    lines=["payment_set_id,n_gt,TP,FP,FN,precision,recall,f1,high,medium,low,trivy_risk_score"]

    for du in sorted(glob.glob(os.path.join(args.datasets_root,"payment_set_*"))):
        du_id=os.path.basename(du)            # payment_set_0001
        set_num = du_id.split("_")[-1]        # 0001
        sarif=os.path.join(args.artifacts_root, f"{set_num}_trivy.sarif")
        if not os.path.exists(sarif):
            print(f"[WARN] missing SARIF for {du_id}; skipping"); continue
        gt = load_gt(du)
        findings = load_sarif(sarif, du)
        tp,fp,fn = match(gt, findings, tol=2)
        sv = sev(findings)
        prec = round(tp/(tp+fp),3) if tp+fp else 0.0
        rec  = round(tp/(tp+fn),3) if tp+fn else 0.0
        f1   = round((2*prec*rec)/(prec+rec),3) if prec+rec else 0.0
        lines.append(f"{du_id},{len(gt)},{tp},{fp},{fn},{prec},{rec},{f1},{sv['high']},{sv['medium']},{sv['low']},{risk_score(sv)}")

    out=os.path.join(args.artifacts_root,"trivy_metrics.csv")
    with open(out,"w") as f: f.write("\n".join(lines))
    print(f"[OK] wrote {out}")
