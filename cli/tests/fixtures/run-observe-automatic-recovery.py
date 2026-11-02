"""Run real Chromium/native and built NativeSurface once; retain both exits."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

base = Path(__file__).resolve().parent
native_checkout = base.parents[2]
sdk_checkout = Path(os.environ["OBSERVE_BRIDGE_E2E_CHECKOUT"])
evidence = Path(os.environ["OBSERVE_AUTOMATIC_EVIDENCE"])
if not evidence.is_absolute():
    raise SystemExit("OBSERVE_AUTOMATIC_EVIDENCE must be an absolute new directory")
evidence.mkdir(mode=0o700, exist_ok=False)
binary = Path(os.environ["OBSERVE_BRIDGE_TEST_BINARY"])
native_command = [str(binary), "continuation_joint_browser_automatic_recovery", "--ignored", "--test-threads=1", "--show-output"]
sdk_command = [os.environ["OBSERVE_BRIDGE_NODE"], "--experimental-transform-types", str(base / "observe-automatic-recovery.mts")]
result = {"nativeCommand": native_command, "sdkCommand": sdk_command, "nativeBinarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "rustTestThreadStackBytes": 33554432, "fixtureLaunch": {"explicitChromeExecutable": os.environ["OBSERVE_AUTOMATIC_CHROME"], "headless": True, "args": ["--no-sandbox"], "ciPresent": "CI" in os.environ}}
result["nativeBaseCommit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=native_checkout, text=True).strip()
result["sdkCommit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=sdk_checkout, text=True).strip()
result["sdkTree"] = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=sdk_checkout, text=True).strip()
result["sdkWorktreeClean"] = not subprocess.check_output(["git", "status", "--porcelain"], cwd=sdk_checkout, text=True).strip()
result["nativeSurfaceDistSha256"] = hashlib.sha256((sdk_checkout / "packages/web/dist/native-surface.js").read_bytes()).hexdigest()
result["sourceFileSha256"] = {
    str(file.relative_to(native_checkout)): hashlib.sha256(file.read_bytes()).hexdigest()
    for file in [native_checkout / "cli/src/native/client_browser.rs", native_checkout / "cli/src/native/client_observation_dispatch.rs", native_checkout / "cli/src/native/client_observe_continuation_tests.rs", native_checkout / "cli/src/native/client_observe_joint_browser_tests.rs", base / "observe-automatic-recovery.mts", base / "observe-automatic-transport.py", Path(__file__).resolve()]
}
with tempfile.TemporaryDirectory(prefix="observe-automatic-") as private:
    ready = Path(private) / "ready.json"
    env = dict(os.environ, RUST_MIN_STACK="33554432", OBSERVE_AUTOMATIC_SOCKET=str(Path(private) / "wire.sock"), OBSERVE_AUTOMATIC_READY=str(ready), OBSERVE_AUTOMATIC_WIRE=str(evidence / "wire.jsonl"), OBSERVE_AUTOMATIC_NATIVE_EVIDENCE=str(evidence / "native-summary.json"), E2E_AGENT_BROWSER_EXECUTABLE=str(base / "observe-automatic-transport.py"))
    with (evidence / "native.log").open("w") as native_log, (evidence / "sdk.log").open("w") as sdk_log:
        native = subprocess.Popen(native_command, env=env, stdout=native_log, stderr=subprocess.STDOUT)
        until = time.monotonic() + 25
        while not ready.exists() and native.poll() is None and time.monotonic() < until:
            time.sleep(0.02)  # readiness only; no browser-work retry
        try:
            sdk = subprocess.run(sdk_command, env=env, stdout=sdk_log, stderr=subprocess.STDOUT, timeout=65)
            result["sdkExit"] = sdk.returncode
        except subprocess.TimeoutExpired:
            result["sdkExit"] = "timeout"
        try:
            result["nativeExit"] = native.wait(timeout=60)
        except subprocess.TimeoutExpired:
            native.kill()
            native.wait()
            result["nativeExit"] = "timeout-killed"
(evidence / "results.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
if result["sdkExit"] != 0 or result["nativeExit"] != 0:
    raise SystemExit("automatic joint recovery failed; original evidence retained")
