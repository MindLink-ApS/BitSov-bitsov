#!/usr/bin/env python3
"""BUG-PSI regression: a paid first contact must deliver, and pay admission once.

Two MOCK `konsensus` nodes on loopback, shaped like the launcher's `reply` case
that lost sats before the fix:

  A: price_open, chat 2,000 msat, lists B in [[peers]] with auto_connect, so A
     dials B and holds B privileged.
  B: price_open, chat 2,000 msat, no peers, so B holds A unprivileged.

B then pays A (the reply-to-dialler direction). Before the fix B's own P2 gate
dropped A's PrekeyOffer after B had paid A's admission: compose returned
502 payment_settled_send_incomplete after 25 s, and nothing was delivered.

Scenarios (default: all):
  reply           B adds A with POST /peers (as the launcher did), then composes.
  reply_unlisted  B composes without listing A: the payer-side grant alone.
  control         A composes to B first (the tester guide's order), then B replies.

Passes (exit 0) when, in every scenario, each compose returns 200 delivered,
B pays at most one admission plus each message, the second message pays the
message only, each first contact (the compose that pays admission) returns
within FIRST_CONTACT_MAX_S, and after B's admission settled B's log shows no
dropped PrekeyOffer from A. Fails (exit 1) otherwise.

Timing (PSI-SPEED): first contact used to wait for one 15 s E2EE self-heal
tick (about 12 s observed). The payee now offers its prekey on promotion and
the payer offers right after its proof (and answers the payee's offer), so the
session forms within round trips of the payment.

Mock only: shared_mock Lightning and a mock chain, fresh loopback ports, and
on macOS `sandbox-exec` with network limited to loopback. It stops only the
processes it starts. Usage:

  scripts/regress/bug_psi.py --bin target/debug/konsensus [scenario ...]
  scripts/regress/bug_psi.py --bin ./konsensus --keep ./bug-psi-out reply

Path note: ``--bin`` and ``--keep`` are resolved to absolute paths at parse
time. Nodes start with ``cwd`` set to their data root, so a relative
``loopback.sb`` (or binary) would not be found by ``sandbox-exec``.
"""
import argparse, base64, hashlib, hmac, json, os, shutil, socket, subprocess, sys, tempfile, time
import urllib.error, urllib.request

CHAT_MSAT = 2_000
# A paid first contact must not wait for a self-heal tick (PSI-SPEED).
FIRST_CONTACT_MAX_S = 2.0
SANDBOX = ('(version 1)\n(allow default)\n(deny network*)\n'
           '(allow network-inbound (local ip "localhost:*"))\n'
           '(allow network-outbound (remote ip "localhost:*"))\n'
           '(allow network-bind (local ip "localhost:*"))\n'
           '(allow network* (local unix-socket) (remote unix-socket))\n')


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Pair:
    """Two throwaway nodes in `run`, A listing B."""

    def __init__(self, binary, run, sandbox):
        self.run, self.sandbox, self.procs = run, sandbox, {}
        os.makedirs(run, mode=0o700)
        self.bin = os.path.join(run, "konsensus")
        shutil.copy(binary, self.bin)
        self.ports = {n: {"api": free_port(), "p2p": free_port()} for n in "ab"}
        self.ids = {}
        for n in "ab":
            root = self.root(n)
            os.makedirs(root, mode=0o700)
            subprocess.run([self.bin, "init", "--dir", root, "--non-interactive", "--tier", "light"],
                           check=True, capture_output=True)
            out = subprocess.run([self.bin, "node-id", "--config", f"{root}/konsensus.toml"],
                                 check=True, capture_output=True, text=True).stdout
            self.ids[n] = out.strip().splitlines()[-1].strip()
            with open(f"{root}/.secret", "w") as f:
                f.write(os.urandom(32).hex())
        for n in "ab":
            self.configure(n)

    def root(self, n):
        return os.path.join(self.run, f"node-{n}")

    def secret(self, n):
        with open(f"{self.root(n)}/.secret") as f:
            return f.read().strip()

    def configure(self, n):
        root, p = self.root(n), self.ports[n]
        peers = ""
        if n == "a":
            peers = (f'\n[[peers]]\nnode_id = "{self.ids["b"]}"\n'
                     f'addr = "127.0.0.1:{self.ports["b"]["p2p"]}"\nlabel = "B"\nauto_connect = true\n')
        cfg = f'''tier = "light"
admission_mode = "price_open"
[identity]
mnemonic_file = "{root}/mnemonic.txt"
passphrase = ""
[network]
listen_addr = "127.0.0.1:{p['p2p']}"
tier = "T1"
[lightning]
backend = "shared_mock"
ledger_path = "{self.run}/mock-ledger.sqlite"
initial_balance_msat = {10_000_000 if n == "a" else 100_000_000}
[chain]
backend = "mock"
[pricing]
mode = "static"
chat_msat = {CHAT_MSAT}
file_ref_msat = 3000
control_msat = 1000
[payment_gate]
verify_lightning_settlement = true
min_admission_cost_msat = 0
[storage]
backend = "sqlite"
path = "{root}/data.db"
encrypted = true
[backup]
scb_dir = "{root}/backups"
[api]
listen_addr = "127.0.0.1:{p['api']}"
jwt_secret = "{self.secret(n)}"
audit_log_path = "{root}/audit.jsonl"
rate_limit_rps = 100
operator_probes_enabled = false
[web]
enabled = false
content_dir = "{root}/pages"
{peers}'''
        # Mock only, never a real wallet or chain.
        assert 'backend = "shared_mock"' in cfg and 'backend = "mock"' in cfg
        with open(f"{root}/konsensus.toml", "w") as f:
            f.write(cfg)

    def token(self, n):
        enc = lambda v: base64.urlsafe_b64encode(json.dumps(v).encode()).rstrip(b"=")
        now = int(time.time())
        claims = {"sub": self.ids[n], "iat": now, "exp": now + 3600, "scp": ["read", "receive", "spend", "admin"]}
        unsigned = enc({"alg": "HS256", "typ": "JWT"}) + b"." + enc(claims)
        sig = base64.urlsafe_b64encode(hmac.new(self.secret(n).encode(), unsigned, hashlib.sha256).digest()).rstrip(b"=")
        return (unsigned + b"." + sig).decode()

    def api(self, n, method, path, body=None, timeout=60):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.ports[n]['api']}/api/v1{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token(n)}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                text = r.read().decode()
                return r.status, (json.loads(text) if text else None)
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            try:
                return e.code, json.loads(text)
            except ValueError:
                return e.code, text

    def start(self, n):
        out = open(f"{self.run}/node-{n}.log", "ab")
        cmd = [self.bin, "start", "--config", f"{self.root(n)}/konsensus.toml"]
        if self.sandbox:
            cmd = ["sandbox-exec", "-f", self.sandbox] + cmd
        self.procs[n] = subprocess.Popen(cmd, cwd=self.root(n), stdout=out, stderr=subprocess.STDOUT,
                                         env={**os.environ, "RUST_LOG": "info"})
        for _ in range(120):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.ports[n]['api']}/api/v1/health", timeout=1)
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError(f"node {n} did not start")

    def stop_all(self):
        for n, p in list(self.procs.items()):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()
            del self.procs[n]

    def connected(self, n, other):
        st, v = self.api(n, "GET", "/peers/connected")
        return st == 200 and self.ids[other] in (v or [])

    def balance(self, n):
        return self.api(n, "GET", "/payments/balance")[1]["balance_msat"]

    def compose(self, frm, to, text):
        started = time.time()
        st, body = self.api(frm, "POST", "/messages/compose", {
            "recipient": self.ids[to], "is_room": False, "kind": 0, "plaintext": text, "max_total_msat": 20_000})
        self.elapsed = time.time() - started
        log(f"{frm.upper()}->{to.upper()} compose HTTP {st} in {self.elapsed:.2f}s:", json.dumps(body)[:300])
        return st, body

    def log_lines(self, n):
        with open(f"{self.run}/node-{n}.log", errors="replace") as f:
            return f.read().splitlines()


def wait(pred, secs):
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.5)
    return False


def scenario(name, binary, workdir, sandbox):
    """Run one scenario; return a list of failures (empty = pass)."""
    failures = []
    check = lambda ok, what: ok or failures.append(what)
    net = Pair(binary, os.path.join(workdir, name), sandbox)
    try:
        net.start("b")
        net.start("a")
        if not (wait(lambda: net.connected("a", "b"), 45) and wait(lambda: net.connected("b", "a"), 10)):
            return [f"{name}: A never connected to B"]
        time.sleep(3)  # PeerConnected handling on both sides

        if name == "control":
            st, body = net.compose("a", "b", "hi from A")
            check(st == 200 and body.get("delivered") is True, f"control: A->B first contact failed: {st} {body}")
            check(net.elapsed < FIRST_CONTACT_MAX_S,
                  f"control: A->B first contact took {net.elapsed:.2f}s (max {FIRST_CONTACT_MAX_S}s)")
        if name == "reply":
            st, _ = net.api("b", "POST", "/peers", {
                "node_id": net.ids["a"], "addr": f"127.0.0.1:{net.ports['a']['p2p']}", "label": "A"})
            check(st == 200, f"reply: POST /peers returned {st}")

        b_before = net.balance("b")
        st, body = net.compose("b", "a", "hola 1")
        check(st == 200 and body.get("delivered") is True, f"{name}: B->A #1 not delivered: {st} {body}")
        first_s = net.elapsed
        paid_1 = b_before - net.balance("b")
        check(paid_1 <= 2 * CHAT_MSAT, f"{name}: B->A #1 paid {paid_1} msat (more than one admission + message)")
        if paid_1 > CHAT_MSAT:  # it paid admission: a first contact
            check(first_s < FIRST_CONTACT_MAX_S,
                  f"{name}: B->A first contact took {first_s:.2f}s (max {FIRST_CONTACT_MAX_S}s)")

        b_before = net.balance("b")
        st, body = net.compose("b", "a", "hola 2")
        check(st == 200 and body.get("delivered") is True, f"{name}: B->A #2 not delivered: {st} {body}")
        paid_2 = b_before - net.balance("b")
        check(paid_2 == CHAT_MSAT, f"{name}: B->A #2 paid {paid_2} msat (expected the message only)")

        # Our own gate must not drop the handshake of a node we paid.
        lines = net.log_lines("b")
        settled = next((i for i, l in enumerate(lines) if "first-contact admission: settled" in l), None)
        if settled is not None:
            drops = [l for l in lines[settled:] if "DROP PrekeyOffer" in l and net.ids["a"] in l]
            check(not drops, f"{name}: B dropped A's PrekeyOffer after paying A: {drops[:2]}")
        log(f"{name}: B paid {paid_1} + {paid_2} msat (#1 in {first_s:.2f}s); admission settled by B: {settled is not None}")
    finally:
        net.stop_all()
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True, help="konsensus binary under test (absolute after parse)")
    ap.add_argument("--keep", help="keep node dirs and logs here (default: a temp dir, removed on pass; absolute after parse)")
    ap.add_argument("--no-sandbox", action="store_true", help="do not wrap nodes in sandbox-exec (non-macOS)")
    ap.add_argument("scenarios", nargs="*", default=["reply", "reply_unlisted", "control"],
                    choices=["reply", "reply_unlisted", "control"])
    args = ap.parse_args()
    # Absolute before any node start: sandbox-exec -f and the binary are resolved
    # from each node's data-dir cwd, not from the caller's cwd.
    args.bin = os.path.abspath(args.bin)
    if args.keep:
        args.keep = os.path.abspath(args.keep)

    workdir = os.path.abspath(args.keep or tempfile.mkdtemp(prefix="bug-psi-"))
    os.makedirs(workdir, exist_ok=True)
    sandbox = None
    if not args.no_sandbox and shutil.which("sandbox-exec"):
        sandbox = os.path.join(workdir, "loopback.sb")
        with open(sandbox, "w") as f:
            f.write(SANDBOX)

    failures = []
    for name in args.scenarios:
        log(f"── {name}")
        failures += scenario(name, args.bin, workdir, sandbox)
    if failures:
        for f in failures:
            log("FAIL", f)
        log("logs kept in", workdir)
        return 1
    log("PASS", ", ".join(args.scenarios))
    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
