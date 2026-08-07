#!/usr/bin/env bash
# End-to-end notify smoke test inside Linux (Docker).
# Creates a metafile, deletes it -> expects call_recording_finished (and others if armed).
set -euo pipefail

ROOT="${ROOT:-/rtpengine}"
WORK="${WORK:-/tmp/notify_e2e_work}"
SPOOL="$WORK/spool"
OUTDIR="$WORK/out"
LOGDIR="$WORK/logs"
EVTLOG="$LOGDIR/notify_events.jsonl"
RECV_PORT=8099
RECV_URL="http://127.0.0.1:${RECV_PORT}/rec/events"

rm -rf "$WORK"
mkdir -p "$SPOOL" "$OUTDIR" "$LOGDIR"

write_section() {
  # write_section FILE SECTION CONTENT
  local f="$1" sec="$2" content="$3"
  local len
  len=$(printf '%s' "$content" | wc -c)
  printf '%s\n%u:\n%s\n\n' "$sec" "$len" "$content" >>"$f"
}

echo "== starting notify receiver =="
python3 "$ROOT/t/notify_e2e/notify_receiver.py" "$EVTLOG" "$RECV_PORT" \
  >"$LOGDIR/receiver.out" 2>"$LOGDIR/receiver.err" &
RECV_PID=$!
sleep 0.4
if ! kill -0 "$RECV_PID" 2>/dev/null; then
  echo "receiver failed to start" >&2
  cat "$LOGDIR/receiver.err" >&2 || true
  exit 1
fi

DAEMON_PID=""
cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
  [[ -n "${RECV_PID:-}" ]] && kill "$RECV_PID" 2>/dev/null || true
  [[ -n "${DAEMON_PID:-}" ]] && wait "$DAEMON_PID" 2>/dev/null || true
  [[ -n "${RECV_PID:-}" ]] && wait "$RECV_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "== starting rtpengine-recording =="
# Prefer in-tree binary: image-built path, then $ROOT, then PATH
BIN=""
for cand in \
  /opt/rtpengine/recording-daemon/rtpengine-recording \
  /rtpengine/recording-daemon/rtpengine-recording \
  "$ROOT/recording-daemon/rtpengine-recording"
do
  if [[ -x "$cand" ]]; then BIN="$cand"; break; fi
done
if [[ -z "$BIN" ]]; then
  BIN=$(command -v rtpengine-recording || true)
fi
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
  echo "rtpengine-recording binary not found" >&2
  ls -la /rtpengine/recording-daemon 2>/dev/null | head || true
  ls -la /opt/rtpengine/recording-daemon 2>/dev/null | head || true
  exit 1
fi
echo "using binary: $BIN"


"$BIN" \
  --foreground \
  --log-stderr \
  --log-level=7 \
  --table=0 \
  --spool-dir="$SPOOL" \
  --output-dir="$OUTDIR" \
  --output-storage=file \
  --output-format=wav \
  --output-single \
  --num-threads=2 \
  --notify-uri="$RECV_URL" \
  --notify-json \
  --notify-events=opened,started,finished,discarded,failed,call-started,call-finished,call-discarded \
  --notify-concurrency=2 \
  --notify-retries=1 \
  >"$LOGDIR/daemon.out" 2>"$LOGDIR/daemon.err" &
DAEMON_PID=$!
sleep 1.0
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
  echo "daemon failed to start" >&2
  cat "$LOGDIR/daemon.err" >&2 || true
  exit 1
fi
echo "daemon pid=$DAEMON_PID receiver pid=$RECV_PID"

# ---- scenario 1: call finished (no streams) ----
CALL="testcall-$(date +%s)"
META="$SPOOL/$CALL"
echo "== writing metafile $META =="
: >"$META"
write_section "$META" "CALL-ID" "$CALL"
write_section "$META" "RANDOM_TAG" "aabbccddeeff0011"
write_section "$META" "METADATA" "foo:bar|test:notify-e2e"
write_section "$META" "RECORDING" "1"
# Ensure CLOSE_WRITE by rewriting via temp + mv? inotify watches close_write of file.
# Writing then closing by sync/open-close cycle:
python3 - <<PY
from pathlib import Path
p = Path("$META")
data = p.read_bytes()
p.write_bytes(data)  # rewrite + close
print("meta bytes", len(data))
PY
sleep 0.8

echo "== deleting metafile (triggers call terminal notify) =="
rm -f "$META"
sleep 1.5

# ---- scenario 2: call discarded path via RECORDING off? still terminal ----
CALL2="discard-$(date +%s)"
META2="$SPOOL/$CALL2"
: >"$META2"
write_section "$META2" "CALL-ID" "$CALL2"
write_section "$META2" "RANDOM_TAG" "1122334455667788"
write_section "$META2" "METADATA" "case:discard"
write_section "$META2" "RECORDING" "0"
python3 - <<PY
from pathlib import Path
p=Path("$META2"); p.write_bytes(p.read_bytes())
PY
sleep 0.5
rm -f "$META2"
sleep 1.5

echo "== events received =="
if [[ ! -s "$EVTLOG" ]]; then
  echo "FAIL: no notify events captured" >&2
  echo "--- daemon.err ---"; tail -80 "$LOGDIR/daemon.err" || true
  echo "--- receiver.err ---"; tail -40 "$LOGDIR/receiver.err" || true
  exit 2
fi

python3 - "$EVTLOG" <<'PY'
import json, sys
from pathlib import Path
log = Path(sys.argv[1])
rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
print(f"total_events={len(rows)}")
events = []
for r in rows:
    h = {k.lower(): v for k, v in r.get("headers", {}).items()}
    ev = h.get("x-recording-event") or (r.get("body_json") or {}).get("event")
    st = h.get("x-recording-status") or (r.get("body_json") or {}).get("status")
    cid = h.get("x-recording-call-id") or (r.get("body_json") or {}).get("call_id")
    events.append(ev)
    print(f" - method={r['method']} event={ev} status={st} call_id={cid} body_json={'yes' if r.get('body_json') else 'no'}")
    if r.get("body_json"):
        print("   json keys:", sorted(r["body_json"].keys()))

need = {"call_recording_finished"}
got = set(e for e in events if e)
missing = need - got
if missing:
    print("FAIL missing required events:", sorted(missing))
    print("got:", events)
    sys.exit(3)
if not any(r.get("body_json") for r in rows):
    print("FAIL: expected JSON bodies (notify-json)")
    sys.exit(4)
print("E2E_NOTIFY_OK")
PY


echo "== sample event log =="
cat "$EVTLOG"
echo
echo "DONE"
