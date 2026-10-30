"""Exercise the SDK against CardPress's independent pyca peer; synthetic keys only."""
import argparse
import importlib.util
import json
import pathlib
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--peer", type=pathlib.Path, required=True)
parser.add_argument("--probe", type=pathlib.Path, required=True)
parser.add_argument("--require-s16", action="store_true")
parser.add_argument("--full", action="store_true", help="Require S16, boundary, and negative cases")
args = parser.parse_args()
spec = importlib.util.spec_from_file_location("peer", args.peer)
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)  # Missing pyca dependencies must fail, never skip.


class QualificationCard(peer.Card):
    """Only adds a plaintext-checking test INS; SCP cryptography stays in the peer."""
    def execute(self, command):
        if command[1] == 0xDA:
            data = self.unwrap(command)
            assert data == bytes(range(len(data))), "protected plaintext mismatch"
            return b"", 0x9000
        return super().execute(command)


def run(name, protocol, option, mode="random", fault=None):
    card = QualificationCard(name)
    failure = None
    calls = []
    challenge_bytes = None
    p = subprocess.Popen([str(args.probe.resolve()), str(protocol), str(option), mode],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result = None
    for line in p.stdout:
        if line.startswith("RESULT "):
            result = line.strip()
            continue
        if not line.startswith("APDU "):
            continue
        try:
            command = bytes.fromhex(line[5:].strip())
            ins = command[1]
            calls.append(ins)
            if ins == 0x50:
                challenge_bytes = command[4]
            if mode == "suite" and ins == 0xDA and calls.count(0xDA) in (1, 7):
                assert command[4] == card.mac_size, "empty command unexpectedly encrypted"
            response = card.transmit(command)
            data, sw = bytes.fromhex(response["data"]), response["sw"]
            if ins == 0x50 and fault:
                n = card.mac_size
                if fault == "bad-cryptogram":
                    at = 13 + 2 * n - 1
                    data = data[:at] + bytes([data[at] ^ 1]) + data[at + 1:]
                elif fault == "bad-challenge":
                    data = data[:13] + bytes([data[13] ^ 1]) + data[14:]
                elif fault == "truncated":
                    data = data[:-1]
                elif fault == "trailing":
                    data += b"\x00"
                elif fault == "wrong-mode":
                    data = data[:12] + bytes([data[12] ^ 1]) + data[13:]
                elif fault == "reserved-option":
                    data = data[:12] + bytes([data[12] | 8]) + data[13:]
                elif fault == "missing-sequence":
                    data = data[:-3]
                elif fault == "unexpected-sequence":
                    data += b"\x00\x00\x01"
                elif fault == "transport":
                    p.stdin.write("!\n"); p.stdin.flush(); continue
                elif fault == "wrong-length-sw":
                    data, sw = b"", 0x6700
            if ins == 0x82 and fault == "reject-external":
                data, sw = b"", 0x6300
            reply = data.hex() + format(sw, "04x")
        except Exception as error:
            failure = type(error).__name__ + ": " + str(error)
            reply = "!"
        p.stdin.write(reply + "\n"); p.stdin.flush()
    p.stdin.close()
    stderr = p.stderr.read()
    code = p.wait()
    negative = fault is not None or mode in ("bad-length", "null-length", "missing-aid", "rmac") or option & 0x08
    if negative:
        ok = result is not None and result.startswith("RESULT authenticate 1")
        ok &= calls.count(0x50) <= 1 and calls.count(0x82) == (1 if fault == "reject-external" else 0)
        ok &= calls.count(0xF2) == 0
        if mode in ("bad-length", "null-length", "rmac") or option & 0x08:
            ok &= calls == [0xA4]
    else:
        ok = result == "RESULT registry 0 count=1"
        ok &= challenge_bytes == (16 if name.startswith("scp03-s16") else 8)
        ok &= calls.count(0x50) == 1 and calls.count(0x82) == 1
        if mode == "suite":
            ok &= calls.count(0xDA) == 7  # Overflow must not reach transport.
    return dict(protocol=name, mode=mode, fault=fault, calls=len(calls),
                initialize_challenge_bytes=challenge_bytes, result=result,
                peer_failure=failure, exit=code, passed=bool(ok and code == 0 and failure is None and not stderr), stderr=stderr)


profiles = [("scp02", 2, 0x55), ("scp03", 3, 0), ("scp03-pseudo", 3, 0x10),
            ("scp03-s16", 3, 1), ("scp03-s16-pseudo", 3, 0x11)]
results = [run(*profile) for profile in profiles]
if args.full:
    results.append(run(*profiles[0], "suite"))
    for profile in profiles[1:]:
        results += [run(*profile, mode) for mode in ("fixed", "suite", "bad-length", "null-length", "rmac")]
        faults = ["bad-cryptogram", "truncated", "trailing", "wrong-mode", "reserved-option",
                  "transport", "reject-external", "wrong-length-sw"]
        faults += ["bad-challenge", "missing-sequence"] if profile[0].endswith("-pseudo") else ["unexpected-sequence"]
        results += [run(*profile, "fixed", fault) for fault in faults]
        results.append(run(profile[0], profile[1], profile[2] | 0x08, "fixed"))
        if profile[0].endswith("-pseudo"):
            results.append(run(*profile, "missing-aid"))
print(json.dumps(results, indent=2))
required = results if args.require_s16 or args.full else results[:3]
raise SystemExit(0 if all(result["passed"] for result in required) else 1)
