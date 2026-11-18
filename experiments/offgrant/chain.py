"""Shared helpers for the OffGrant end-to-end harness (contracts v6): Web3 access to PureChain (Clique),
transaction sending with local nonces, contract deployment from Foundry artifacts, and the digests, operation
encodings, states, checkpoint Merkle trees and history accumulators that mirror contracts/src/OffLib.sol exactly.

Tuples follow the Solidity structs field by field:
  Op     = (kind, key, epoch, reading, base, until, amount, total, version, clockSig)
  State  = (epoch, reading, resources, totals, versions, objects, opens, releases)
  Header = (site, height, histRoot, opsRoot, opCount, stateHash, stateLen, tip, closeEpoch, closeReading, closeSig)
"""
import json
import threading
import time
from pathlib import Path

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT / "contracts" / "out"

CONSUME, USE, LOG, RELEASE, ACK, SHARE = 1, 2, 3, 4, 5, 6
ATTESTED = (CONSUME, USE, RELEASE, ACK)
OPEN = 2**64 - 1   # hold that lasts until released
HIST_DEPTH = 32
MAX_STATE = 64
ZERO = b"\x00" * 32


def connect(port, timeout=4):
    w = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{port}", request_kwargs={"timeout": timeout}))
    w.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)  # Clique extraData > 32 bytes
    return w


def artifact(name):
    a = json.loads((ART / f"{name}.sol" / f"{name}.json").read_text())
    return a["abi"], a["bytecode"]["object"]


class Sender:
    """Signs and sends legacy zero-gas transactions from one key with a local nonce."""

    def __init__(self, w3, key):
        self.w3 = w3
        self.acct = Account.from_key(key)
        self.lock = threading.Lock()
        self.nonce = None
        self.chain_id = None

    def _sync(self):
        self.nonce = self.w3.eth.get_transaction_count(self.acct.address, "pending")
        self.chain_id = self.w3.eth.chain_id

    def send(self, fn=None, *, to=None, data=b"", gas=3_000_000, wait=True, timeout=60):
        with self.lock:
            if self.nonce is None:
                self._sync()
            tx = {"gas": gas, "gasPrice": 0, "nonce": self.nonce, "chainId": self.chain_id, "value": 0}
            if fn is not None:
                tx = fn.build_transaction({**tx, "from": self.acct.address})
            else:
                tx.update(to=to, data=data)
            raw = self.acct.sign_transaction(tx).raw_transaction
            try:
                h = self.w3.eth.send_raw_transaction(raw)
            except Exception:
                self.nonce = None  # resync on the next send
                raise
            self.nonce += 1
        if not wait:
            return h
        return self.w3.eth.wait_for_transaction_receipt(h, timeout=timeout, poll_latency=0.25)

    def send_robust(self, fn, *, gas=3_000_000, deadline=120.0, rebroadcast=4.0, on_sent=None):
        """Signs once and keeps rebroadcasting the same raw transaction (same nonce, same hash) until it is mined or
        the deadline passes, so a lossy or flapping link delays a transaction but cannot lose or duplicate it."""
        with self.lock:
            if self.nonce is None:
                self._sync()
            tx = fn.build_transaction({"gas": gas, "gasPrice": 0, "nonce": self.nonce, "chainId": self.chain_id,
                                       "value": 0, "from": self.acct.address})
            raw = self.acct.sign_transaction(tx).raw_transaction
            self.nonce += 1
        h = keccak(raw)
        if on_sent:
            on_sent(h)
        t_end, last = time.time() + deadline, 0.0
        while time.time() < t_end:
            if time.time() - last >= rebroadcast:
                try:
                    self.w3.eth.send_raw_transaction(raw)
                except Exception:  # noqa: BLE001  already known / mined / link down: keep polling
                    pass
                last = time.time()
            try:
                r = self.w3.eth.get_transaction_receipt(h)
                if r is not None:
                    return r
            except Exception:  # noqa: BLE001  not yet mined, or the link is down
                pass
            time.sleep(0.5)
        with self.lock:
            self.nonce = None  # the transaction may still land; resync before the next one
        raise TimeoutError(f"transaction {h.hex()} not mined within {deadline} s")

    def deploy(self, name, *args):
        abi, bytecode = artifact(name)
        c = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        r = self.send(c.constructor(*args), gas=12_000_000)
        assert r.status == 1, f"deploy {name} failed"
        return self.w3.eth.contract(address=r.contractAddress, abi=abi), r


def at(w3, name, address):
    return w3.eth.contract(address=address, abi=artifact(name)[0])


# ------------------------------------------------------------------------- digests (mirror OffLib.sol)
def _h(types, values):
    return keccak(encode(types, values))


def domain(registry, chain_id):
    return _h(["string", "uint256", "address"], ["OFFGRANT-v6", chain_id, registry])


def checkpoint_digest(dom, header_hash_):
    return _h(["string", "bytes32", "bytes32"], ["OFFGRANT-CKPT", dom, header_hash_])


def clock_digest(dom, site, epoch, reading, tag):
    return _h(["string", "bytes32", "uint64", "uint64", "uint64", "bytes32"],
              ["OFFGRANT-CLOCK", dom, site, epoch, reading, tag])


def objects_hash(objects):
    return _h(["bytes32[]"], [list(objects)])


def request_tag(objs_hash):
    return _h(["string", "bytes32"], ["OFFGRANT-REQ", objs_hash])


def renewal_digest(dom, site, objs_hash, epoch, cq, issued):
    return _h(["string", "bytes32", "uint64", "bytes32", "uint64", "uint64", "uint64"],
              ["OFFGRANT-RENEW", dom, site, objs_hash, epoch, cq, issued])


def stop_digest(dom, site, obj, epoch, cq):
    return _h(["string", "bytes32", "uint64", "bytes32", "uint64", "uint64"], ["OFFGRANT-STOP", dom, site, obj, epoch, cq])


def ack_digest(dom, site, obj, epoch, reading):
    return _h(["string", "bytes32", "uint64", "bytes32", "uint64", "uint64"], ["OFFGRANT-ACK", dom, site, obj, epoch, reading])


def share_digest(dom, site, resource, amount, version):
    return _h(["string", "bytes32", "uint64", "bytes32", "uint64", "uint64"],
              ["OFFGRANT-SHARE", dom, site, resource, amount, version])


def lease_digest(dom, site, obj, allowance, is_open):
    return _h(["string", "bytes32", "uint64", "bytes32", "uint64", "bool"],
              ["OFFGRANT-LEASE", dom, site, obj, allowance, is_open])


def sign(key, digest):
    s = Account.unsafe_sign_hash(digest, key)
    return s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big") + bytes([s.v])


def signer(digest, sig):
    """Address that signed `digest` (as OffLib.recover); None on a malformed signature."""
    try:
        return Account._recover_hash(digest, signature=sig)
    except Exception:  # noqa: BLE001
        return None


def certified_by(digest, sigs, authorities, threshold):
    """Whether at least `threshold` distinct authorities signed `digest` (as SiteRights._certified)."""
    return len({a for a in (signer(digest, s) for s in sigs) if a in authorities}) >= threshold


# ------------------------------------------------------------------------- operations and states
def op_tag(op):
    kind, key, _e, _r, base, until, amount, _t, version, _s = op
    return _h(["string", "uint8", "bytes32", "uint64", "uint64", "uint64", "uint64"],
              ["OFFGRANT-OP", kind, key, base, until, amount, version])


def op_leaf(op):
    kind, key, e, r, base, until, amount, total, version, sig = op
    return _h(["uint8", "bytes32", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "bytes32"],
              [kind, key, e, r, base, until, amount, total, version, keccak(sig)])


def make_op(kind, key, epoch=0, reading=0, base=0, until=0, amount=0, total=0, version=0, sig=b""):
    return (kind, key, epoch, reading, base, until, amount, total, version, sig)


def attest_op(clock, dom, site, op):
    """Attests an operation at its (epoch, reading) with the site clock; returns the op with its signature."""
    sig = sign(clock.key, clock_digest(dom, site, op[2], op[3], op_tag(op)))
    return op[:9] + (sig,)


def state_hash(st):
    epoch, reading, resources, totals, versions, objects, opens, releases = st
    return _h(["string", "uint64", "uint64", "bytes32[]", "uint64[]", "uint64[]", "bytes32[]", "uint64[]", "uint64[]"],
              ["OFFGRANT-STATE", epoch, reading, list(resources), list(totals), list(versions), list(objects),
               list(opens), list(releases)])


def state_len(st):
    return len(st[2]) + len(st[5])


class SiteState:
    """The state a correct validator tracks from the site ledger's operations (mirrors what checkpoints commit):
    the newest attested reading, per resource its running total and share version, and per object with open holds
    the number of open holds ever applied and of releases."""

    def __init__(self):
        self.epoch, self.reading = 0, 0
        self.total, self.version = {}, {}
        self.opens, self.releases = {}, {}

    def apply(self, op):
        kind, key, e, r = op[0], op[1], op[2], op[3]
        if kind in ATTESTED:
            self.epoch, self.reading = e, r
        if kind == CONSUME:
            self.total[key] = op[7]
            self.version[key] = max(self.version.get(key, 0), op[8])
        elif kind == SHARE:
            self.version[key] = op[8]
            self.total.setdefault(key, op[7])
        elif kind == USE and op[5] == OPEN:
            self.opens[key] = op[7]
            self.releases.setdefault(key, 0)
        elif kind == RELEASE:
            self.releases[key] = op[7]

    def tuple(self):
        keys = sorted(set(self.total) | set(self.version))
        objs = sorted(self.opens)
        return (self.epoch, self.reading, keys, [self.total.get(k, 0) for k in keys],
                [self.version.get(k, 0) for k in keys], objs, [self.opens[o] for o in objs],
                [self.releases.get(o, 0) for o in objs])

    def copy(self):
        s = SiteState()
        s.epoch, s.reading = self.epoch, self.reading
        s.total, s.version = dict(self.total), dict(self.version)
        s.opens, s.releases = dict(self.opens), dict(self.releases)
        return s


def lookup(st, key):
    for k, t, v in zip(st[2], st[3], st[4]):
        if k == key:
            return t, v
    return 0, 0


def lookup_obj(st, obj):
    for k, o, r in zip(st[5], st[6], st[7]):
        if k == obj:
            return o, r
    return 0, 0


# ------------------------------------------------------------------------- Merkle trees
def _pair(l, r):
    return keccak(l + r)  # abi.encode(bytes32, bytes32) is the plain concatenation


def merkle(leaves):
    """Root and per-leaf proofs; an odd node is paired with itself (as in OffLib.verifyLeaf)."""
    if not leaves:
        return ZERO, []
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        lv = levels[-1]
        levels.append([_pair(lv[i], lv[i + 1] if i + 1 < len(lv) else lv[i]) for i in range(0, len(lv), 2)])
    proofs = []
    for idx in range(len(leaves)):
        p, i = [], idx
        for lv in levels[:-1]:
            sib = i ^ 1
            p.append(lv[sib] if sib < len(lv) else lv[i])
            i >>= 1
        proofs.append(p)
    return levels[-1][0], proofs


_ZEROS = [ZERO]
for _ in range(HIST_DEPTH):
    _ZEROS.append(_pair(_ZEROS[-1], _ZEROS[-1]))


def _hist_levels(hist):
    levels = [list(hist)]
    for d in range(HIST_DEPTH):
        lv = levels[-1]
        levels.append([_pair(lv[i], lv[i + 1] if i + 1 < len(lv) else _ZEROS[d]) for i in range(0, len(lv), 2)])
    return levels


def hist_root(hist):
    """History accumulator over hist[i] = hash of the checkpoint at height i (hist[0] = ZERO)."""
    if not hist:
        return _ZEROS[HIST_DEPTH]
    return _hist_levels(hist)[HIST_DEPTH][0]


def hist_path(hist, idx):
    levels, p, i = _hist_levels(hist), [], idx
    for d in range(HIST_DEPTH):
        lv = levels[d]
        sib = i ^ 1
        p.append(lv[sib] if sib < len(lv) else _ZEROS[d])
        i >>= 1
    return p


# ------------------------------------------------------------------------- checkpoints
def content_tag(h):
    return _h(["string", "uint64", "uint64", "bytes32", "bytes32", "uint64", "bytes32", "uint64", "bytes32"],
              ["OFFGRANT-CLOSE", *h[:8]])


def header_hash(h):
    return _h(["bytes32", "uint64", "uint64"], [content_tag(h), h[8], h[9]])


def make_header(clock, dom, site, hist, ops, state, tip):
    """Builds the checkpoint at height len(hist) over `ops`, with the state after them; the trusted clock attests
    its close over the content (OffLib.contentTag)."""
    assert state_len(state) <= MAX_STATE, "state above MAX_STATE"
    root, proofs = merkle([op_leaf(op) for op in ops])
    epoch, reading = clock.epoch, clock.read()
    h = (site, len(hist), hist_root(hist), root, len(ops), state_hash(state), state_len(state), tip, epoch, reading,
         b"")
    sig = sign(clock.key, clock_digest(dom, site, epoch, reading, content_tag(h)))
    return h[:10] + (sig,), proofs


class Clock:
    """A site's trusted clock (TPM 2.0 Clock stand-in): milliseconds that advance at rate 1 + drift, stop across
    a power loss (new epoch), and attest (epoch, reading). Readings handed out are strictly increasing."""

    def __init__(self, key, site, drift, t0):
        self.key, self.site, self.drift = key, site, drift
        self.epoch = 1
        self.offset = 10_000_000.0  # an arbitrary positive TPM Clock value (ms)
        self.base_real = time.time()
        self._last = 0
        self._lock = threading.Lock()

    def read(self):
        with self._lock:
            r = int(self.offset + (time.time() - self.base_real) * (1 + self.drift) * 1000)
            r = max(r, self._last + 1)
            self._last = r
            return r

    def reset(self):
        """Power loss: Clock keeps its last value (it does not advance while off) and the epoch changes."""
        with self._lock:
            self.offset = max(self._last, int(self.offset + (time.time() - self.base_real) * (1 + self.drift) * 1000))
            self.base_real = time.time()
            self.epoch += 1
            self._last = 0
