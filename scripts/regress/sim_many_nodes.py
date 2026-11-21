#!/usr/bin/env python3
"""Many-node sandbox simulation, one `konsensus` process per node.

The in-process simulation (`konsensus-node` `sim_many_nodes.rs`) cannot send from
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
unreadable messages; see the in-process simulation for the focused regression).
Some first contacts on a busy node may also return 502
payment_settled_send_incomplete (the admission is disclosed and a retry does
not pay it again); that cause is tracked separately.

Invariants checked after the traffic settles:
  I0 paid traffic happened: at least one compose was acked and every acked
     (sender, recipient) pair settled at least one payment;
  I1 every compose that returned 200 delivered=true is delivered exactly once
     across all nodes, at its recipient, from its sender; a failed compose is
     delivered at most once, and never at another node;
  I2 no sim plaintext appears that was not sent;
  I4 the ledger conserves money; no compose reports more than its cap; per
     (payer, payee), every settled payment is explained exactly: a message
     payment by the payment_hash its compose reported, and every other
     payment by an admission or re-admission a compose reported (its amount
     minus its message payment, plus readmission_msat). Reported money that
     never settled, and any payment left over, are violations. Only a compose
     cut by its own node's restart (outcome unknown) explains leftover
     payments, up to its all-in cap. The pair never settles more than the sum
     of its composes' caps;
  I5 no compose hangs past the deadline or loses its connection, unless its
     own node was restarted under it: the connection was lost (not timed out)
     and the request was in flight while the restart ran; no node process
     exits or panics.

Every compose states max_total_msat (MAX_TOTAL_MSAT) and max_routing_fee_msat:
first contact and re-admission need an explicit aggregate cap. The controller talks to the
nodes through an opener with no proxies, so requests stay on loopback.

Usage:
  scripts/regress/sim_many_nodes.py --bin target/debug/konsensus --nodes 10 --steps 6 --seed 1
  scripts/regress/sim_many_nodes.py --bin ./konsensus --nodes 20 --restart 0.3 --keep ./sim-out
"""
import argparse, base64, concurrent.futures, hashlib, hmac, http.client, json, os, random, shutil, socket, sqlite3
import subprocess, sys, tempfile, time, urllib.error, urllib.request

CHAT_MSAT = 2_000
# Routing-fee allowance per payment (the shared mock ledger charges no fee).
ROUTING_FEE_MSAT = 1_000
# All-in aggregate cap per compose: the message, plus a first-contact admission
# or a re-admission after a reconnect (each one chat price under static
# pricing), each with its routing-fee allowance.
MAX_TOTAL_MSAT = 3 * (CHAT_MSAT + ROUTING_FEE_MSAT)
START_MSAT = 50_000_000
COMPOSE_TIMEOUT_S = 75
# Messages per listing page (the API's maximum), and how many pages one
# inbox read may take before it is refused as runaway paging.
PAGE_LIMIT = 1000
MAX_PAGES = 200
SANDBOX = ('(version 1)\n(allow default)\n(deny network*)\n'
           '(allow network-inbound (local ip "localhost:*"))\n'
           '(allow network-outbound (remote ip "localhost:*"))\n'
           '(allow network-bind (local ip "localhost:*"))\n'
           '(allow network* (local unix-socket) (remote unix-socket))\n')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# Never an inherited HTTP proxy, never a redirect: the controller only talks
# to the loopback nodes it started.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


class ListingIncomplete(Exception):
    """An inbox could not be read to its end: a page failed or paging ran away."""


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

    def api(self, i, method, path, body=None, timeout=30, headers_out=None):
        """(status, json body); `headers_out`, if given, receives the response headers."""
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.ports[i]['api']}/api/v1{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token(i)}", "Content-Type": "application/json"})
        # The outer handlers also cover reading an error body: a restarting
        # node can send error headers and close mid body.
        try:
            try:
                with OPENER.open(req, timeout=timeout) as r:
                    text = r.read().decode()
                    if headers_out is not None:
                        headers_out.update({k.lower(): v for k, v in r.headers.items()})
                    return r.status, (json.loads(text) if text else None)
            except urllib.error.HTTPError as e:
                with e:
                    text = e.read().decode()
                try:
                    return e.code, json.loads(text)
                except ValueError:
                    return e.code, text
        except (TimeoutError, socket.timeout):
            return None, "timeout"
        except urllib.error.URLError as e:
            if isinstance(e.reason, (TimeoutError, socket.timeout)):
                return None, "timeout"  # a connect timeout, wrapped
            return None, f"unreachable: {e.reason}"
        except (http.client.HTTPException, ConnectionError) as e:
            # The node closed or reset the connection mid-request (restart chaos).
            return None, f"dropped: {type(e).__name__}: {e}"

    def start(self, i):
        out = open(f"{self.run}/node-{i}.log", "ab")
        cmd = [self.bin, "start", "--config", f"{self.root(i)}/konsensus.toml"]
        if self.sandbox:
            cmd = ["sandbox-exec", "-f", self.sandbox] + cmd
        self.procs[i] = subprocess.Popen(cmd, cwd=self.root(i), stdout=out, stderr=subprocess.STDOUT,
                                         env={**os.environ, "RUST_LOG": os.environ.get("SIM_RUST_LOG", "info")})
        for _ in range(240):
            try:
                OPENER.open(f"http://127.0.0.1:{self.ports[i]['api']}/api/v1/health", timeout=1).close()
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
        """Every message at node i, newest first, across all pages.

        The list is keyset-paged on (timestamp, id) descending. A page names
        its continuation in X-BitSov-Next-Before(-Id) when the scan stopped
        early (unreadable rows, scan budget); otherwise a full page continues
        from its last message. A page shorter than the limit with no
        continuation header ends the listing. A failed page, a cursor that
        does not move, or more than MAX_PAGES pages raise ListingIncomplete:
        a truncated inbox must never pass for a complete one.
        """
        out, cursor, seen = [], None, set()
        for page in range(1, MAX_PAGES + 1):
            path = f"/messages?limit={PAGE_LIMIT}"
            if cursor is not None:
                path += f"&before={cursor[0]}&before_id={cursor[1]}"
            headers = {}
            st, v = self.api(i, "GET", path, headers_out=headers)
            if st != 200 or not isinstance(v, list):
                raise ListingIncomplete(f"n{i} page {page}: {st} {str(v)[:120]}")
            out += v
            if "x-bitsov-next-before" in headers and "x-bitsov-next-before-id" in headers:
                nxt = (headers["x-bitsov-next-before"], headers["x-bitsov-next-before-id"])
            elif len(v) >= PAGE_LIMIT:
                nxt = (str(v[-1].get("timestamp")), str(v[-1].get("id")))
            else:
                return out
            if nxt == cursor or nxt in seen:
                raise ListingIncomplete(f"n{i}: paging cursor {nxt} did not advance")
            seen.add(nxt)
            cursor = nxt
        raise ListingIncomplete(f"n{i}: more than {MAX_PAGES} pages of {PAGE_LIMIT}")

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


def money_violations(sent, payments):
    """I4 per (payer, payee) over the settled ledger payments (payer, payee, msat, hash).

    A compose's reported money is its message payment (found by the
    payment_hash it reported) plus the admission or re-admission it reported:
    amount_msat (message + any first-contact admission) - the message
    payment + readmission_msat. Each reported admission consumes settled
    payments of exactly its amount; reported money that did not settle is a
    violation. Whatever is left is explained only by composes cut by their
    own node's restart (`interrupted`: outcome unknown), each up to its
    all-in cap; with none, any leftover payment is a violation.
    """
    v = []
    pairs = {}
    for r in sent:
        pairs.setdefault((r["from"], r["to"]), ([], []))[0].append(r)
    for row in payments:
        pairs.setdefault((row[0], row[1]), ([], []))[1].append(row)
    for (p, q), (sends, rows) in sorted(pairs.items()):
        total = sum(row[2] for row in rows)
        if not sends:
            v.append(f"I4 n{p} paid n{q} {len(rows)}x/{total} msat but never sent to it")
            continue
        cap = len(sends) * MAX_TOTAL_MSAT
        if total > cap:
            v.append(f"I4 over cap n{p}->n{q}: ledger {len(rows)}/{total} msat > {len(sends)} compose(s) x max_total_msat = {cap}")
        left = list(rows)
        admissions, interrupted = [], 0
        for r in sends:
            if r["interrupted"]:
                interrupted += 1
                continue
            body = r["body"]
            reported = (body.get("amount_msat") or 0) + (body.get("readmission_msat") or 0)
            if reported > MAX_TOTAL_MSAT:
                v.append(f"I4 cap: n{p}->n{q} reported {reported} msat over its max_total_msat {MAX_TOTAL_MSAT}")
            message = 0
            h = body.get("payment_hash")
            hit = next((k for k, row in enumerate(left) if h and row[3] == h), None)
            if hit is not None:
                message = left.pop(hit)[2]
            elif h:
                # A reported message payment must have settled; its money is never
                # reclassified as admission, so unrelated payments cannot stand in.
                v.append(f"I4 message unsettled n{p}->n{q}: reported message payment {h}, which never settled")
                continue
            if reported < message:
                v.append(f"I4 under-reported n{p}->n{q}: reported {reported} msat, its message payment {h} settled {message}")
            elif reported > message:
                admissions.append((r, reported - message))
        left.sort(key=lambda row: -row[2])
        for r, want in admissions:
            need, k = want, 0
            while need and k < len(left):
                if left[k][2] <= need:
                    need -= left.pop(k)[2]
                else:
                    k += 1
            if need:
                v.append(f"I4 unsettled n{p}->n{q} {r['text']!r}: reported {want} msat of admission/re-admission, "
                         f"{need} msat of it has no settled payment")
        extra = sum(row[2] for row in left)
        if extra and extra > interrupted * MAX_TOTAL_MSAT:
            v.append(f"I4 unexplained n{p}->n{q}: {len(left)} payment(s)/{extra} msat match no reported message, "
                     f"admission or re-admission ({interrupted} interrupted compose(s) explain at most "
                     f"{interrupted * MAX_TOTAL_MSAT}; hashes {[row[3][:16] for row in left]})")
    return v


def simulate(args, workdir, sandbox):
    rng = random.Random(args.seed)
    net = Net(args.bin, os.path.join(workdir, f"seed-{args.seed}"), args.nodes, sandbox)
    started = time.time()
    violations, notes, sent = [], [], []
    try:
        # One at a time: nodes funding the shared mock ledger at once can
        # fail to start with "database is locked".
        for i in range(args.nodes):
            net.start(i)
        time.sleep(2)
        edges = set()
        for a in range(args.nodes):
            for _ in range(args.degree):
                b = rng.randrange(args.nodes)
                if a != b and (min(a, b), max(a, b)) not in edges:
                    if net.dial(a, b):
                        edges.add((min(a, b), max(a, b)))
                    else:
                        notes.append(f"dial n{a}->n{b} failed")
        log(f"mesh: {len(edges)} edges, {time.time() - started:.1f}s")

        def compose(job):
            step, a, b, text = job
            t0 = time.monotonic()
            st, body = net.api(a, "POST", "/messages/compose",
                               {"recipient": net.ids[b], "kind": 0, "plaintext": text,
                                "max_routing_fee_msat": ROUTING_FEE_MSAT, "max_total_msat": MAX_TOTAL_MSAT},
                               timeout=COMPOSE_TIMEOUT_S)
            t1 = time.monotonic()
            return {"step": step, "from": a, "to": b, "text": text, "status": st,
                    "body": body if isinstance(body, dict) else {"raw": body}, "secs": t1 - t0,
                    "began": t0, "ended": t1, "interrupted": False}

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
                jobs.append((step, a, b, f"sim:{args.seed}:{step}:n{a}>n{b}:{len(sent) + len(jobs)}"))
            # Chaos: restart one node mid-step.
            victim = rng.randrange(args.nodes) if rng.random() < args.restart else None
            delay = rng.uniform(0.05, 1.5)
            down = None  # (stop began, start finished) of the deliberate restart
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs) + 1) as pool:
                futs = [pool.submit(compose, j) for j in jobs]
                if victim is not None:
                    time.sleep(delay)
                    log(f"step {step}: restarting n{victim}")
                    stop_at = time.monotonic()
                    net.stop(victim)
                    net.start(victim)
                    down = (stop_at, time.monotonic())
                results = [f.result() for f in futs]
            for r in results:
                # The sender's own process went away under this compose: the
                # outcome is unknown, not a hang. It may still have paid (up
                # to its cap) and may still be delivered (at most once). Only
                # a lost connection (never a timeout) of a request still in
                # flight when the restart began; a compose that had already
                # failed before it keeps its I5 violation.
                raw = str(r["body"].get("raw", ""))
                if (down is not None and r["status"] is None and r["from"] == victim
                        and raw.startswith(("dropped", "unreachable"))
                        and r["ended"] >= down[0] and r["began"] <= down[1]):
                    r["interrupted"] = True
                    notes.append(f"interrupted n{r['from']}->n{r['to']} by its restart: {raw[:120]}")
            sent += results
            if victim is not None:
                for e in list(edges):
                    if victim in e:
                        other = e[0] if e[1] == victim else e[1]
                        net.dial(victim, other)
            ok = sum(1 for r in results if acked(r))
            log(f"step {step}: {len(results)} sends, {ok} ok, t={time.time() - started:.1f}s")

        # Settle, then check.
        want = {(r["to"], r["text"]) for r in sent if claims_delivery(r)}
        inbox, unread = {}, {}

        def refresh():
            for i in range(args.nodes):
                try:
                    inbox[i] = net.messages(i)
                    unread.pop(i, None)
                except ListingIncomplete as e:
                    inbox.setdefault(i, [])
                    unread[i] = str(e)
            if unread:
                return False
            got = {(i, m.get("plaintext")) for i, ms in inbox.items() for m in ms}
            return want <= got
        wait(refresh, 30)
        time.sleep(5)
        refresh()

        for i, why in sorted(unread.items()):
            violations.append(f"I1 inbox of n{i} not read to its end: {why}")
        texts = {r["text"]: r for r in sent}
        seen = {}
        for i, ms in inbox.items():
            for m in ms:
                p = m.get("plaintext") or ""
                if not p.startswith("sim:"):
                    continue
                r = texts.get(p)
                if r is None:
                    violations.append(f"I2 unsent plaintext at n{i}: {p!r}")
                    continue
                if i == r["from"] and m.get("sender") == net.ids[i]:
                    continue  # the sender's own copy of what it sent
                seen.setdefault(p, []).append(i)
                if i != r["to"]:
                    violations.append(f"I1 {p!r} (n{r['from']}->n{r['to']}) delivered at n{i}")
                if m.get("sender") != net.ids[r["from"]]:
                    violations.append(f"I1 {p!r} at n{i} from {m.get('sender')}, sent by n{r['from']}")
        for r in sent:
            ok = claims_delivery(r)
            hits = len(seen.get(r["text"], []))
            if ok and hits != 1:
                undecrypted = [m["id"][:16] for m in inbox.get(r["to"], [])
                               if m.get("sender") == net.ids[r["from"]] and not m.get("plaintext")]
                violations.append(f"I1 n{r['from']}->n{r['to']} {r['text']!r} delivered {hits}x across nodes "
                                  f"(message_id {r['body'].get('message_id')}; undecrypted from sender: {undecrypted})")
            if not ok and hits > 1:
                violations.append(f"I1 failed send n{r['from']}->n{r['to']} delivered {hits}x across nodes")
            if r["status"] is None and not r["interrupted"]:
                violations.append(f"I5 compose n{r['from']}->n{r['to']} {r['body']}")
            if not acked(r):
                notes.append(f"failed n{r['from']}->n{r['to']} {r['status']} {json.dumps(r['body'])[:220]}")

        db = sqlite3.connect(net.ledger())
        balances = dict(db.execute("SELECT owner, balance FROM accounts"))
        total = sum(balances.values())
        if total != args.nodes * START_MSAT:
            violations.append(f"I4 ledger holds {total}, expected {args.nodes * START_MSAT}")
        idx = {h: i for i, h in enumerate(net.ids)}
        payments = [(idx[payer], idx[recipient], amount, h) for payer, recipient, amount, h in db.execute(
            "SELECT payer, recipient, amount, hash FROM invoices WHERE payer IS NOT NULL")
            if payer in idx and recipient in idx]
        paid = {}
        for p, q, amount, _ in payments:
            paid[(p, q)] = (paid.get((p, q), (0, 0))[0] + 1, paid.get((p, q), (0, 0))[1] + amount)
        violations += money_violations(sent, payments)

        acked_pairs = {(r["from"], r["to"]) for r in sent if acked(r)}
        if not acked_pairs:
            violations.append(f"I0 no paid traffic: none of {len(sent)} composes was acked")
        for (p, q) in sorted(acked_pairs):
            if paid.get((p, q), (0, 0))[0] == 0:
                violations.append(f"I0 n{p}->n{q} acked without a settled payment")

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
