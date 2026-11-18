"""Generate local PureChain (Clique) networks for the experiments.

Layouts
  span      one chain of 12 signers spread over three sites (4 each) on one Docker network: the
            "single ledger across sites" setting in which a cut-off site is a Clique minority.
  offgrant  the proposed architecture: a global chain G (4 signers) and one chain per site (4 signers each),
            each on its own Docker network, plus one uplink proxy per site on G's network. A site's relayer
            reaches G only through its proxy, so cutting the proxy (netem loss 100%) cuts that site's uplink.

Writes testbed/purechain/net_<layout>/: keys (throwaway), keystores, genesis per chain, static peers,
docker-compose.yml and nodes.json (names, addresses, RPC ports). Keys never leave this git-ignored folder.

Usage: python mknet.py span|offgrant [--sites 2]
"""
import argparse
import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path

from eth_account import Account
from eth_keys import keys

HERE = Path(__file__).resolve().parent
IMAGE = "offgrant/purechain:1.0.1"
PASSWORD = "offgrant-testnet"  # throwaway local keystores only
PERIOD = 1


def node_keys():
    k = "0x" + secrets.token_hex(32)
    nk = secrets.token_hex(32)
    return dict(
        key=k,
        address=Account.from_key(k).address,
        nodekey=nk,
        pub=keys.PrivateKey(bytes.fromhex(nk)).public_key.to_hex()[2:],
    )


def _bash():
    """Git Bash on Windows (the bare `bash` there may be WSL, which cannot see this path)."""
    for c in (os.environ.get("BASH_EXE"), r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")):
        if c and os.path.exists(c):
            return c
    raise SystemExit("bash not found; set BASH_EXE")


def genesis(chain_id, signers):
    out = subprocess.run(
        [_bash(), (HERE / "upstream" / "gen-genesis.sh").as_posix(), str(chain_id), *signers],
        check=True, capture_output=True, text=True,
    ).stdout
    g = json.loads(out)
    g["config"]["clique"]["period"] = PERIOD
    return g


def write_node(root, n, g):
    d = root / n["name"]
    (d / "keystore").mkdir(parents=True, exist_ok=True)
    ks = Account.encrypt(n["key"], PASSWORD, kdf="pbkdf2", iterations=2 ** 14)
    (d / "keystore" / f"UTC--{n['address'][2:].lower()}").write_text(json.dumps(ks))
    (d / "pw").write_text(PASSWORD)
    (d / "nodekey").write_text(n["nodekey"])
    (d / "genesis.json").write_text(json.dumps(g, indent=1))


def static_peers(root, nodes):
    for n in nodes:
        peers = [f'"enode://{m["pub"]}@{m["ip"]}:30303"' for m in nodes if m is not n]
        (root / n["name"] / "config.toml").write_text(
            "[Node.P2P]\nStaticNodes = [" + ", ".join(peers) + "]\nTrustedNodes = [" + ", ".join(peers) + "]\n"
        )


def service(n, chain_id, nets):
    cmd = [
        "--datadir", "/data", "--config", "/data/config.toml", "--networkid", str(chain_id),
        "--unlock", n["address"], "--password", "/data/pw", "--allow-insecure-unlock",
        "--mine", "--miner.etherbase", n["address"], "--miner.gasprice", "0", "--txpool.pricelimit", "0",
        "--syncmode", "full", "--gcmode", "archive", "--snapshot=false", "--cache", "64",
        "--nodiscover", "--port", "30303", "--nodekey", "/data/nodekey",
        "--http", "--http.addr", "0.0.0.0", "--http.port", "8545", "--http.vhosts", "*",
        "--http.api", "eth,net,web3,admin,miner,txpool,clique,debug", "--verbosity", "2",
    ]
    return {
        "image": IMAGE,
        "container_name": n["name"],
        "command": cmd,
        "volumes": [f"./{n['name']}:/data"],
        "ports": [f"127.0.0.1:{n['rpc']}:8545"],
        "cap_add": ["NET_ADMIN"],
        "networks": {net: {"ipv4_address": ip} for net, ip in nets},
        "restart": "unless-stopped",
        "mem_limit": "256m",
    }


def init_datadir(root, n):
    host = str(root / n["name"])
    subprocess.run(
        ["docker", "run", "--rm", "-v", f"{host}:/data", IMAGE, "--datadir", "/data", "init", "/data/genesis.json"],
        check=True, capture_output=True, env={**os.environ, "MSYS_NO_PATHCONV": "1"},
    )


def chain(root, label, chain_id, net, subnet_prefix, count, rpc_base, nodes_out, services, extra_nets=()):
    nodes = []
    for i in range(count):
        n = node_keys()
        n.update(name=f"{label}{i + 1}", ip=f"{subnet_prefix}.{11 + i}", rpc=rpc_base + i, chain=label,
                 chain_id=chain_id)
        nodes.append(n)
    g = genesis(chain_id, [n["address"] for n in nodes])
    for n in nodes:
        write_node(root, n, g)
    static_peers(root, nodes)
    for n in nodes:
        services[n["name"]] = service(n, chain_id, [(net, n["ip"])])
        init_datadir(root, n)
    nodes_out[label] = nodes
    return nodes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("layout", choices=["span", "offgrant"])
    ap.add_argument("--sites", type=int, default=2)
    args = ap.parse_args()
    root = HERE / f"net_{args.layout}"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    services, networks, nodes = {}, {}, {}

    if args.layout == "span":
        networks["spannet"] = {"ipam": {"config": [{"subnet": "172.33.0.0/24"}]}}
        allnodes = []
        for s, label in enumerate(["a", "b", "c"]):
            for i in range(4):
                n = node_keys()
                n.update(name=f"span{label}{i + 1}", ip=f"172.33.0.{11 + 20 * s + i}", rpc=8600 + 10 * s + i,
                         chain="span", chain_id=9300, site=label)
                allnodes.append(n)
        g = genesis(9300, [n["address"] for n in allnodes])
        for n in allnodes:
            write_node(root, n, g)
        static_peers(root, allnodes)
        for n in allnodes:
            services[n["name"]] = service(n, 9300, [("spannet", n["ip"])])
            init_datadir(root, n)
        nodes["span"] = allnodes
    else:
        networks["gnet"] = {"ipam": {"config": [{"subnet": "172.34.0.0/24"}]}}
        chain(root, "g", 9101, "gnet", "172.34.0", 4, 8700, nodes, services)
        for k in range(1, args.sites + 1):
            net = f"s{k}net"
            networks[net] = {"ipam": {"config": [{"subnet": f"172.35.{k}.0/24"}]}}
            chain(root, f"s{k}", 9200 + k, net, f"172.35.{k}", 4, 8700 + 10 * k, nodes, services)
            # Uplink proxy of site k: the only path from site k's relayer to G.
            services[f"up{k}"] = {
                "image": IMAGE, "container_name": f"up{k}", "entrypoint": ["socat"],
                "command": ["TCP-LISTEN:8545,fork,reuseaddr", "TCP:172.34.0.11:8545"],
                "ports": [f"127.0.0.1:{8790 + k}:8545"], "cap_add": ["NET_ADMIN"],
                "networks": {"gnet": {"ipv4_address": f"172.34.0.{40 + k}"}}, "restart": "unless-stopped",
                "mem_limit": "32m",
            }
            nodes.setdefault("uplinks", []).append({"site": k, "name": f"up{k}", "rpc": 8790 + k})

    compose = {"name": f"offgrant-{args.layout}", "services": services, "networks": networks}
    (root / "docker-compose.yml").write_text(json.dumps(compose, indent=1))
    (root / "nodes.json").write_text(json.dumps(nodes, indent=1))
    print(f"wrote {root} with {len(services)} services")


if __name__ == "__main__":
    main()
