"""Shared helpers for the OffGrant end-to-end harness: Web3 access to PureChain (Clique), transaction sending
with local nonces, contract deployment from Foundry artifacts, and the digests, signatures and checkpoint
Merkle trees that mirror contracts/src/OffLib.sol exactly."""
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

CONSUME, USE, LOG = 1, 2, 3


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

    def deploy(self, name, *args):
        abi, bytecode = artifact(name)
        c = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        r = self.send(c.constructor(*args), gas=8_000_000)
        assert r.status == 1, f"deploy {name} failed"
        return self.w3.eth.contract(address=r.contractAddress, abi=abi), r


def at(w3, name, address):
    return w3.eth.contract(address=address, abi=artifact(name)[0])


# ------------------------------------------------------------------------- digests (mirror OffLib.sol)
def _h(types, values):
    return keccak(encode(types, values))


def checkpoint_digest(registry, header_hash):
    return _h(["string", "address", "bytes32"], ["OFFGRANT-CKPT", registry, header_hash])


def clock_digest(site, epoch, reading, tag):
    return _h(["string", "uint64", "uint64", "uint64", "bytes32"], ["OFFGRANT-CLOCK", site, epoch, reading, tag])


def request_digest(site, obj, epoch, cq):
    return _h(["string", "uint64", "bytes32", "uint64", "uint64"], ["OFFGRANT-REQ", site, obj, epoch, cq])


def renewal_digest(registry, site, obj, epoch, cq, issued):
    return _h(["string", "address", "uint64", "bytes32", "uint64", "uint64", "uint64"],
              ["OFFGRANT-RENEW", registry, site, obj, epoch, cq, issued])


def stop_digest(registry, site, obj, epoch, cq):
    return _h(["string", "address", "uint64", "bytes32", "uint64", "uint64"],
              ["OFFGRANT-STOP", registry, site, obj, epoch, cq])


def ack_digest(registry, site, obj, epoch, reading):
    return _h(["string", "address", "uint64", "bytes32", "uint64", "uint64"],
              ["OFFGRANT-ACK", registry, site, obj, epoch, reading])


def share_digest(registry, site, resource, amount):
    return _h(["string", "address", "uint64", "bytes32", "uint64"], ["OFFGRANT-SHARE", registry, site, resource, amount])


def lease_digest(registry, site, obj, allowance):
    return _h(["string", "address", "uint64", "bytes32", "uint64"], ["OFFGRANT-LEASE", registry, site, obj, allowance])


def sign(key, digest):
    s = Account.unsafe_sign_hash(digest, key)
    return s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big") + bytes([s.v])


# ------------------------------------------------------------------------- checkpoints
def op_leaf(op):
    kind, key, a, b, e, sig = op
    return _h(["uint8", "bytes32", "uint64", "uint64", "uint64", "bytes32"], [kind, key, a, b, e, keccak(sig)])


def _pair(l, r):
    return keccak(l + r)  # abi.encode(bytes32, bytes32) is the plain concatenation


def merkle(leaves):
    """Root and per-leaf proofs; an odd node is paired with itself (as in OffLib.verifyLeaf)."""
    if not leaves:
        return b"\x00" * 32, []
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


def header_hash(h):
    site, height, prev, root, count, close = h
    return _h(["uint64", "uint64", "bytes32", "bytes32", "uint64", "uint64"], [site, height, prev, root, count, close])


class Clock:
    """A site's trusted clock (TPM 2.0 Clock stand-in): milliseconds that advance at rate 1 + drift, stop
    across a power loss (new epoch), and attest (epoch, reading) with the clock key."""

    def __init__(self, key, site, drift, t0):
        self.key, self.site, self.drift = key, site, drift
        self.epoch = 1
        self.offset = 10_000_000.0  # an arbitrary positive TPM Clock value (ms)
        self.base_real = time.time()

    def read(self):
        return int(self.offset + (time.time() - self.base_real) * (1 + self.drift) * 1000)

    def reset(self):
        """Power loss: Clock keeps its last value (it does not advance while off) and the epoch changes."""
        self.offset = self.read()
        self.base_real = time.time()
        self.epoch += 1

    def attest(self, digest_fn, *args):
        return sign(self.key, digest_fn(*args))
