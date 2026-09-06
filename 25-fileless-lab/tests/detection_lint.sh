#!/bin/bash
# Lint the detection content extracted from blocks 21-24.
# Checks the Sigma YAML parses and reports which Sigma spec fields the doc omits,
# and sanity-checks the auditd rule syntax with auditctl where available.
cat > /tmp/lint.py <<'PY'
import glob, os, sys
try:
    import yaml
except ImportError:
    sys.exit("pyyaml missing")

REQUIRED = ("title", "logsource", "detection")          # Sigma mandatory
RECOMMENDED = ("id", "status", "description", "author", "date", "references")

for f in sorted(glob.glob("/d/*.yml")):
    name = os.path.basename(f)
    try:
        d = yaml.safe_load(open(f).read())
    except Exception as e:
        print("  FAILS   %s: %s" % (name, e))
        continue
    miss_req = [k for k in REQUIRED if k not in d]
    miss_rec = [k for k in RECOMMENDED if k not in d]
    print("  PARSES  %s" % name)
    print("          condition: %s" % d.get("detection", {}).get("condition"))
    if miss_req:
        print("          MISSING REQUIRED: %s" % ", ".join(miss_req))
    print("          omitted (doc excerpt, not a deployable rule): %s" % ", ".join(miss_rec))
PY
python3 /tmp/lint.py

echo
echo "=== auditd rule syntax ==="
if command -v auditctl >/dev/null; then
  grep -v '^\s*#' /d/audit-fileless.rules | grep -v '^\s*$' | while read -r r; do
    # -R needs a file; feed each rule and report parse-only outcome
    printf '%s\n' "$r" > /tmp/one.rules
    err=$(auditctl -R /tmp/one.rules 2>&1)
    case "$err" in
      # Field-parse failure: auditctl rejected the rule TEXT. A real defect.
      *"not supported by kernel"*|*"Syntax error"*|*"Unknown"*)
        echo "  BAD-SYNTAX  $r"
        echo "              -> $(printf '%s' "$err" | grep -v 'status request' | head -1)" ;;
      # Netlink write refused: rule parsed fine, we just lack privilege / no audit
      # subsystem in this container. NOT a defect in the rule.
      *"Operation not permitted"*)
        echo "  PARSES-OK   $r  (load blocked: no audit subsystem in container)" ;;
      "") echo "  LOADED      $r" ;;
      *)  echo "  OTHER       $r -> $(printf '%s' "$err" | head -1)" ;;
    esac
  done
else
  echo "  auditctl not installed; structural check only:"
  grep -c '^-a always,exit' /d/audit-fileless.rules | sed 's/^/    rules: /'
  grep -o '\-k [a-z_]*' /d/audit-fileless.rules | sort -u | sed 's/^/    key: /'
fi
