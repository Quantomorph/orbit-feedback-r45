#!/bin/sh
# ORBIT A1 — full suite. No network, no credentials, no model, no live capital.
# RUNTIME CONTRACT: POSIX (Linux / WSL2 / container), local filesystem.
# See orbit/runtime.py; startup refuses anything else rather than failing later.
# AUDIT GUARANTEE: see orbit/audit/checkpoint.py for the exact, narrowed claim.
cd "$(dirname "$0")" || exit 1
python3 -c "from orbit.runtime import describe; print(describe())"
echo
fail=0
for f in tests/test_*.py; do
  printf '%-45s ' "$f"
  python3 "$f" >/tmp/orbit_out.$$ 2>&1 && grep -E '^RESULTS' /tmp/orbit_out.$$ || { fail=1; tail -25 /tmp/orbit_out.$$; }
  rm -f /tmp/orbit_out.$$
done
exit $fail
