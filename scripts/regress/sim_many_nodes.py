#!/usr/bin/env python3
"""Many-node sandbox simulation, one `konsensus` process per node.

The in-process harness (`konsensus-node` `sim_many_nodes.rs`) cannot send from
two nodes to the same recipient: compose keeps its first-contact admission
ledger, admission locks and quote cache in process-wide statics keyed by the
recipient only. This runner starts N real node processes instead, so any
node may pay any other: many-to-one first contacts, crossing first contacts,
fan-in, and optional restarts mid-traffic.

Mock only: every node uses `shared_mock` Lightning (one SQLite ledger, regtest
invoices, no funds) and the `mock` chain, listens on 127.0.0.1 only, and on
macOS runs under `sandbox-exec` limited to loopback. It stops only the
processes it starts. The seed fixes the traffic schedule (who sends to whom,
who restarts); identities come from `konsensus init` and differ per run, and
OS scheduling is not fixed, so a failing seed reproduces the shape, usually
but not always the same failure.

Known finding this runner shows: BUG-SIM-1 (one-time prekey reuse: acked but
unreadable messages; see the in-process harness for the focused regression).
Some first contacts on a busy node may also return 502
payment_settled_send_incomplete (the admission is disclosed and a retry does
not pay it again); that cause is tracked separately.

Invariants checked after the traffic settles:
  I1 every compose that returned 200 delivered=true is in the recipient's
     message list exactly once, with its plaintext, from its sender;
  I2 no sim plaintext appears that was not sent;
  I4 the ledger conserves money; per (payer, payee), settled msat <= what the
     compose responses reported + one admission per connection epoch;
  I5 no compose hangs past the deadline; no node process exits or panics.

Usage:
  scripts/regress/sim_many_nodes.py --bin target/debug/konsensus --nodes 10 --steps 6 --seed 1
  scripts/regress/sim_many_nodes.py --bin ./konsensus --nodes 20 --restart 0.3 --keep ./sim-out
"""
import argparse, base64, concurrent.futures, hashlib, hmac, json, os, random, shutil, socket, sqlite3
import subprocess, sys, tempfile, time, urllib.error, urllib.request

CHAT_MSAT = 2_000
START_MSAT = 50_000_000
COMPOSE_TIMEOUT_S = 75
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


class Net:
    def __init__(self, binary, run, n, sandbox):
        self.run, self.n, self.sandbox, self.procs = run, n, sandbox, {}
        os.makedirs(run, mode=0o700, exist_ok=True)
        self.bin = os.path.join(run, "konsensus")
        shutil.copy(binary, self.bin)
        self.ports = [{"api": free_port(), "p2p": free_port()} for _ in range(n)]
        self.ids, self.secrets = [], []
        for i in range(n):
            root = self.root(i)
            os.makedirs(root, mode=0o700)
            subprocess.run([self.bin, "init", "--dir", root, "--non-interactive", "--tier", "light"],
                           check=True, capture_output=True)
            out = subprocess.run([self.bin, "node-id", "--config", f"{root}/konsensus.toml"],
                                 check=True, capture_output=True, text=True).stdout
            self.ids.append(out.strip().splitlines()[-1].strip())
            self.secrets.append(os.urandom(32).hex())
            self.configure(i)

    def root(self, i):
        return os.path.join(self.run, f"node-{i}")

    def ledger(self):
        return os.path.join(self.run, "mock-ledger.sqlite")

    def configure(self, i):
        root, p = self.root(i), self.ports[i]
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
ledger_path = "{self.ledger()}"
initial_balance_msat = {START_MSAT}
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
jwt_secret = "{self.secrets[i]}"
audit_log_path = "{root}/audit.jsonl"
rate_limit_rps = 1000
operator_probes_enabled = false
[web]
enabled = false
content_dir = "{root}/pages"
'''
        # Mock only, never a real wallet or chain.
        assert 'backend = "shared_mock"' in cfg and 'backend = "mock"' in cfg
        with open(f"{root}/konsensus.toml", "w") as f:
            f.write(cfg)

    def token(self, i):
        enc = lambda v: base64.urlsafe_b64encode(json.dumps(v).encode()).rstrip(b"=")
        now = int(time.time())
        claims = {"sub": self.ids[i], "iat": now, "exp": now + 3600, "scp": ["read", "receive", "spend", "admin"]}
        unsigned = enc({"alg": "HS256", "typ": "JWT"}) + b"." + enc(claims)
        sig = base64.urlsafe_b64encode(hmac.new(self.secrets[i].encode(), unsigned, hashlib.sha256).digest()).rstrip(b"=")
        return (unsigned + b"." + sig).decode()

    def api(self, i, method, path, body=None, timeout=30):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.ports[i]['api']}/api/v1{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token(i)}", "Content-Type": "application/json"})
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
        except (TimeoutError, socket.timeout):
            return None, "timeout"
        except urllib.error.URLError as e:
            return None, f"unreachable: {e.reason}"

    def start(self, i):
        out = open(f"{self.run}/node-{i}.log", "ab")
        cmd = [self.bin, "start", "--config", f"{self.root(i)}/konsensus.toml"]
        if self.sandbox:
            cmd = ["sandbox-exec", "-f", self.sandbox] + cmd
        self.procs[i] = subprocess.Popen(cmd, cwd=self.root(i), stdout=out, stderr=subprocess.STDOUT,
                                         env={**os.environ, "RUST_LOG": os.environ.get("SIM_RUST_LOG", "info")})
        for _ in range(240):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.ports[i]['api']}/api/v1/health", timeout=1)
                return
            except Exception:
                time.sleep(0.25)
        raise RuntimeError(f"node {i} did not start")

    def stop(self, i):
        p = self.procs.pop(i, None)
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()

    def stop_all(self):
        for i in list(self.procs):
            self.stop(i)

    def connected(self, a, b):
        st, v = self.api(a, "GET", "/peers/connected")
        return st == 200 and self.ids[b] in (v or [])

    def dial(self, a, b):
        st, body = self.api(a, "POST", "/peers", {
            "node_id": self.ids[b], "addr": f"127.0.0.1:{self.ports[b]['p2p']}", "label": f"n{b}"})
        return st == 200 and wait(lambda: self.connected(a, b) and self.connected(b, a), 10)

    def messages(self, i):
        st, v = self.api(i, "GET", "/messages?limit=1000")
        return v if st == 200 and isinstance(v, list) else []

    def log_text(self, i):
        with open(f"{self.run}/node-{i}.log", errors="replace") as f:
            return f.read()


def wait(pred, secs):
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.25)
    return False


def acked(r):
    """Acked by the recipient. `delivered` alone only means handed to the peer."""
    return r["status"] == 200 and r["body"].get("accepted") is True


def claims_delivery(r):
    return acked(r) or (r["status"] == 200 and r["body"].get("delivered") is True and r["body"].get("state") == "sent")


def simulate(args, workdir, sandbox):
    rng = random.Random(args.seed)
    net = Net(args.bin, os.path.join(workdir, f"seed-{args.seed}"), args.nodes, sandbox)
    started = time.time()
    violations, notes, sent = [], [], []
    epochs = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.nodes) as pool:
            list(pool.map(net.start, range(args.nodes)))
        time.sleep(2)
        edges = set()
        for a in range(args.nodes):
            for _ in range(args.degree):
                b = rng.randrange(args.nodes)
                if a != b and (min(a, b), max(a, b)) not in edges:
                    if net.dial(a, b):
                        edges.add((min(a, b), max(a, b)))
                        epochs[(min(a, b), max(a, b))] = epochs.get((min(a, b), max(a, b)), 0) + 1
                    else:
                        notes.append(f"dial n{a}->n{b} failed")
        log(f"mesh: {len(edges)} edges, {time.time() - started:.1f}s")

        def compose(job):
            step, a, b, text = job
            t0 = time.time()
            st, body = net.api(a, "POST", "/messages/compose",
                               {"recipient": net.ids[b], "kind": 0, "plaintext": text}, timeout=COMPOSE_TIMEOUT_S)
            return {"step": step, "from": a, "to": b, "text": text, "status": st,
                    "body": body if isinstance(body, dict) else {"raw": body}, "secs": time.time() - t0}

        for step in range(args.steps):
            senders, jobs = set(), []
            while len(jobs) < args.per_step and len(senders) < args.nodes:
                a, b = rng.randrange(args.nodes), rng.randrange(args.nodes)
                if a == b or a in senders or a not in net.procs or b not in net.procs:
                    if len(senders) >= args.nodes - 1:
                        break
                    continue
                senders.add(a)
                e = (min(a, b), max(a, b))
                if e not in edges:
                    if net.dial(a, b):
                        edges.add(e)
                        epochs[e] = epochs.get(e, 0) + 1
                jobs.append((step, a, b, f"sim:{args.seed}:{step}:n{a}>n{b}:{len(sent) + len(jobs)}"))
            # Chaos: restart one node mid-step.
            victim = rng.randrange(args.nodes) if rng.random() < args.restart else None
            delay = rng.uniform(0.05, 1.5)
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs) + 1) as pool:
                futs = [pool.submit(compose, j) for j in jobs]
                if victim is not None:
                    time.sleep(delay)
                    log(f"step {step}: restarting n{victim}")
                    net.stop(victim)
                    net.start(victim)
                results = [f.result() for f in futs]
            sent += results
            if victim is not None:
                for e in list(edges):
                    if victim in e:
                        other = e[0] if e[1] == victim else e[1]
                        if net.dial(victim, other):
                            epochs[e] = epochs.get(e, 0) + 1
            ok = sum(1 for r in results if acked(r))
            log(f"step {step}: {len(results)} sends, {ok} ok, t={time.time() - started:.1f}s")

        # Settle, then check.
        want = {(r["to"], r["text"]) for r in sent if claims_delivery(r)}
        inbox = {}

        def refresh():
            for i in range(args.nodes):
                inbox[i] = net.messages(i)
            got = {(i, m.get("plaintext")) for i, ms in inbox.items() for m in ms}
            return want <= got
        wait(refresh, 30)
        time.sleep(5)
        refresh()

        texts = {r["text"]: r for r in sent}
        for r in sent:
            ok = claims_delivery(r)
            hits = [m for m in inbox.get(r["to"], []) if m.get("plaintext") == r["text"]]
            if ok and len(hits) != 1:
                undecrypted = [m["id"][:16] for m in inbox.get(r["to"], [])
                               if m.get("sender") == net.ids[r["from"]] and not m.get("plaintext")]
                violations.append(f"I1 n{r['from']}->n{r['to']} {r['text']!r} delivered {len(hits)}x "
                                  f"(message_id {r['body'].get('message_id')}; undecrypted from sender: {undecrypted})")
            if not ok and len(hits) > 1:
                violations.append(f"I1 failed send n{r['from']}->n{r['to']} delivered {len(hits)}x")
            for m in hits:
                if m.get("sender") != net.ids[r["from"]]:
                    violations.append(f"I1 {r['text']!r} at n{r['to']} from {m.get('sender')}")
            if r["status"] is None:
                violations.append(f"I5 compose n{r['from']}->n{r['to']} {r['body']}")
            if not acked(r):
                notes.append(f"failed n{r['from']}->n{r['to']} {r['status']} {json.dumps(r['body'])[:220]}")
        for i, ms in inbox.items():
            for m in ms:
                p = m.get("plaintext") or ""
                if p.startswith("sim:") and p not in texts:
                    violations.append(f"I2 unsent plaintext at n{i}: {p!r}")

        db = sqlite3.connect(net.ledger())
        balances = dict(db.execute("SELECT owner, balance FROM accounts"))
        total = sum(balances.values())
        if total != args.nodes * START_MSAT:
            violations.append(f"I4 ledger holds {total}, expected {args.nodes * START_MSAT}")
        idx = {h: i for i, h in enumerate(net.ids)}
        paid = {}
        for payer, recipient, amount in db.execute("SELECT payer, recipient, amount FROM invoices WHERE payer IS NOT NULL"):
            if payer in idx and recipient in idx:
                k = (idx[payer], idx[recipient])
                paid[k] = (paid.get(k, (0, 0))[0] + 1, paid.get(k, (0, 0))[1] + amount)
        reported = {}
        for r in sent:
            k = (r["from"], r["to"])
            amt = (r["body"].get("amount_msat") or 0) + (r["body"].get("readmission_msat") or 0)
            reported[k] = (reported.get(k, (0, 0))[0] + 1, reported.get(k, (0, 0))[1] + amt)
        for (p, q), (count, msat) in sorted(paid.items()):
            sends = reported.get((p, q), (0, 0))
            ep = max(1, epochs.get((min(p, q), max(p, q)), 0))
            if sends[0] == 0:
                violations.append(f"I4 n{p} paid n{q} {count}x/{msat} msat but never sent to it")
            elif msat > sends[1] + ep * CHAT_MSAT:
                violations.append(f"I4 overcharge n{p}->n{q}: ledger {count}/{msat} msat > reported {sends[1]} + {ep} admission(s)")

        for i in range(args.nodes):
            p = net.procs.get(i)
            if p is None or p.poll() is not None:
                violations.append(f"I5 node n{i} process exited (code {p.poll() if p else 'stopped'})")
            if "panicked at" in net.log_text(i):
                violations.append(f"I5 node n{i} logged a panic")

        statuses = {}
        for r in sent:
            key = "200 acked" if acked(r) else \
                f"{r['status']} {r['body'].get('code', '') or r['body'].get('state', '')}"
            statuses[key] = statuses.get(key, 0) + 1
        log(f"report seed={args.seed} nodes={args.nodes} steps={args.steps} sends={len(sent)} "
            f"payments={sum(c for c, _ in paid.values())} runtime={time.time() - started:.1f}s outcomes={statuses}")
        for n in notes[:30]:
            log("note", n)
    finally:
        net.stop_all()
    return violations, net.run


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--nodes", type=int, default=10)
    ap.add_argument("--steps", type=int, default=5)
    ap.add_argument("--per-step", type=int, default=0, help="concurrent composes per step (default nodes/2)")
    ap.add_argument("--degree", type=int, default=2, help="random dials per node for the initial mesh")
    ap.add_argument("--restart", type=float, default=0.0, help="probability of restarting a node in each step")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", help="keep node dirs and logs here")
    ap.add_argument("--no-sandbox", action="store_true")
    args = ap.parse_args()
    args.bin = os.path.abspath(args.bin)
    args.per_step = args.per_step or max(1, args.nodes // 2)
    workdir = os.path.abspath(args.keep or tempfile.mkdtemp(prefix="sim-many-"))
    os.makedirs(workdir, exist_ok=True)
    sandbox = None
    if not args.no_sandbox and shutil.which("sandbox-exec"):
        sandbox = os.path.join(workdir, "loopback.sb")
        with open(sandbox, "w") as f:
            f.write(SANDBOX)
    log(f"sim: seed={args.seed} nodes={args.nodes} steps={args.steps} per_step={args.per_step} restart={args.restart}")
    violations, run = simulate(args, workdir, sandbox)
    if violations:
        for v in violations:
            log("VIOLATION", v)
        log(f"FAIL ({len(violations)}); rerun: --seed {args.seed} --nodes {args.nodes} --steps {args.steps} "
            f"--per-step {args.per_step} --restart {args.restart}; logs in {run}")
        return 1
    log("PASS")
    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
