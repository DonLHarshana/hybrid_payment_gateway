import argparse, pathlib, shutil, subprocess

ap=argparse.ArgumentParser()
ap.add_argument("--id", required=True)   # e.g., 0001
a=ap.parse_args()

root = pathlib.Path("datasets"); root.mkdir(exist_ok=True)
ps = root / f"payment_set_{a.id}"
if ps.exists(): shutil.rmtree(ps)

subprocess.check_call([
  "python","tools/secrets_injector.py",
  "--template","payment_set_template",
  "--out", str(ps),
  "--gt",  str(ps/"ground_truth"/"secrets.csv")
])

(ps/"metadata.yaml").write_text(f"payment_set_id: {a.id}\n", encoding="utf-8")
print("OK ->", ps)
