"""Run ignored Rust bridge and real Node SDK together; retain both terminal exits."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

base = Path(__file__).resolve().parent
evidence = Path(os.environ["OBSERVE_BRIDGE_EVIDENCE"])
if not evidence.is_absolute():
    raise SystemExit("OBSERVE_BRIDGE_EVIDENCE must be an absolute new directory")
evidence.mkdir(mode=0o700, exist_ok=False)
results = []
for mode in ("continuous", "wrong-owner"):
    with tempfile.TemporaryDirectory(prefix="observe-bridge-") as private:
        socket = Path(private) / "wire.sock"
        env = dict(os.environ, OBSERVE_BRIDGE_SOCKET=str(socket), OBSERVE_BRIDGE_MODE=mode)
        command = [env["OBSERVE_BRIDGE_TEST_BINARY"], "continuation_joint_wire_bridge", "--ignored", "--test-threads=1", "--show-output"]
        with (evidence / f"bridge-{mode}-native.log").open("w") as native_log, (evidence / f"bridge-{mode}-sdk.log").open("w") as sdk_log:
            native = subprocess.Popen(command, env=env, stdout=native_log, stderr=subprocess.STDOUT)
            until = time.monotonic() + 20
            while not socket.exists() and native.poll() is None and time.monotonic() < until:
                time.sleep(0.02)  # socket readiness only, never retry browser work
            sdk_command = [env["OBSERVE_BRIDGE_NODE"], "--experimental-transform-types", str(base / "observe-joint-bridge.mts")]
            try:
                sdk = subprocess.run(sdk_command, env=env, stdout=sdk_log, stderr=subprocess.STDOUT, timeout=25)
                sdk_exit = sdk.returncode
            except subprocess.TimeoutExpired:
                sdk_exit = "timeout"
            try:
                native_exit = native.wait(timeout=40)
            except subprocess.TimeoutExpired:
                native.kill()
                native.wait()
                native_exit = "timeout-killed"
            results.append(dict(mode=mode, nativeCommand=command, sdkCommand=sdk_command, nativeExit=native_exit, sdkExit=sdk_exit))
            (evidence / "bridge-results.json").write_text(json.dumps(results, indent=2) + "\n")
            if native_exit != 0 or sdk_exit != 0:
                raise SystemExit(f"{mode}: native={native_exit} sdk={sdk_exit}; original logs retained")
print(json.dumps(results, indent=2))
