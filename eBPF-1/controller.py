#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time

STATUS_ALLOWED = 1
VLAN_MAX = 4094
FDB_RETRIES = 30

running = True


def log(msg):
    print(f"[controller] {msg}", flush=True)


def stop_handler(_signum, _frame):
    global running
    running = False


def parse_args():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="802.1X/RADIUS enforcement controller: polls auth_map and applies ebtables rules and bridge VLANs")
    parser.add_argument("--iface", default="eth0",
                        help="XDP attachment interface and uplink toward CE2 (default: eth0)")
    parser.add_argument("--bridge", default="bridge0",
                        help="vlan-filtering bridge device (default: bridge0)")
    parser.add_argument("--source", default=os.path.join(script_dir, "radius_xdp.c"),
                        help="path to the eBPF C source (default: radius_xdp.c next to this script)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="auth_map poll interval in seconds (default: 1.0)")
    return parser.parse_args()


def check_root():
    if os.geteuid() != 0:
        sys.exit("[!] this daemon must run as root inside the eBPF-1 node")


def check_binaries():
    for binary in ("ebtables", "bridge"):
        if shutil.which(binary) is None:
            sys.exit(f"[!] required binary not found: {binary}")


def run_cmd(cmd, quiet=False):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        if not quiet:
            log(f"[!] binary not found: {cmd[0]}")
        return None
    if proc.returncode != 0 and not quiet:
        detail = (proc.stderr or proc.stdout).strip()
        log(f"[!] rc={proc.returncode}: {' '.join(cmd)}" + (f" -> {detail}" if detail else ""))
    return proc.returncode


def key_to_mac(key):
    raw = bytes(key.addr) if hasattr(key, "addr") else bytes(key)[:6]
    return ":".join(f"{byte:02x}" for byte in raw)


def scalar_int(value):
    if isinstance(value, int):
        return value
    if hasattr(value, "value"):
        return int(value.value)
    return int.from_bytes(bytes(value), "little")


def fdb_port_for_mac(mac, bridge, uplink):
    try:
        proc = subprocess.run(["bridge", "-j", "fdb", "show", "br", bridge],
                              capture_output=True, text=True)
    except FileNotFoundError:
        return None
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            entries = json.loads(proc.stdout)
        except json.JSONDecodeError:
            entries = []
        for entry in entries:
            if entry.get("mac", "").lower() == mac:
                dev = entry.get("dev", "")
                if dev and dev not in (bridge, uplink):
                    return dev
    try:
        proc = subprocess.run(["bridge", "fdb", "show", "br", bridge],
                              capture_output=True, text=True)
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0].lower() == mac and fields[1] == "dev":
            dev = fields[2]
            if dev not in (bridge, uplink):
                return dev
    return None


def grant_access(mac, vlan, uplink, bridge):
    if run_cmd(["ebtables", "-C", "FORWARD", "-s", mac, "-j", "ACCEPT"], quiet=True) != 0:
        if run_cmd(["ebtables", "-A", "FORWARD", "-s", mac, "-j", "ACCEPT"]) != 0:
            return False
    port = fdb_port_for_mac(mac, bridge, uplink)
    if port is None:
        log(f"[-] FDB entry not ready for {mac}, will retry")
        return False
    run_cmd(["bridge", "vlan", "add", "dev", uplink, "vid", str(vlan)])
    if run_cmd(["bridge", "vlan", "add", "dev", port, "vid", str(vlan), "pvid", "untagged"]) != 0:
        return False
    log(f"[+] access granted: mac={mac} vlan={vlan} port={port}")
    return True


def wait_interval(interval):
    deadline = time.monotonic() + interval
    while running:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def poll_loop(auth_map, iface, bridge, interval):
    known = {}
    pending = {}
    while running:
        try:
            for key, leaf in auth_map.items():
                try:
                    mac = key_to_mac(key)
                    vlan = scalar_int(leaf.vlan_id)
                    status = scalar_int(leaf.status)
                except Exception as exc:
                    log(f"[!] skipping malformed auth entry: {exc}")
                    continue
                if status != STATUS_ALLOWED or not 1 <= vlan <= VLAN_MAX:
                    continue
                if known.get(mac) == vlan:
                    continue
                if mac not in pending:
                    log(f"[*] authenticated: mac={mac} vlan={vlan}")
                    pending[mac] = [vlan, 0]
        except Exception as exc:
            log(f"[!] auth_map read failed: {exc}")
        for mac in list(pending):
            vlan, attempts = pending[mac]
            if grant_access(mac, vlan, iface, bridge):
                known[mac] = vlan
                pending.pop(mac, None)
            elif attempts + 1 >= FDB_RETRIES:
                log(f"[!] giving up on {mac} after {FDB_RETRIES} attempts")
                pending.pop(mac, None)
            else:
                pending[mac] = [vlan, attempts + 1]
        wait_interval(interval)
    log(f"stopped; enforced MACs: {', '.join(sorted(known)) or 'none'}")


def main():
    args = parse_args()
    check_root()
    check_binaries()
    if not os.path.isfile(args.source):
        sys.exit(f"[!] BPF source not found: {args.source}")

    try:
        from bcc import BPF
    except ImportError:
        sys.exit("[!] python3 bcc bindings not available (install python3-bcc)")

    try:
        bpf = BPF(src_file=args.source)
        fn = bpf.load_func("parse_radius", BPF.XDP)
    except Exception as exc:
        sys.exit(f"[!] BPF compilation/load failed: {exc}")

    try:
        bpf.attach_xdp(args.iface, fn, 0)
    except Exception as exc:
        sys.exit(f"[!] XDP attach to {args.iface} failed: {exc} "
                 f"(if another XDP program is attached: ip link set dev {args.iface} xdp off)")

    auth_map = bpf.get_table("auth_map")
    log(f"attached XDP to {args.iface}; polling auth_map every {args.interval}s (CTRL+C to detach)")

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    try:
        poll_loop(auth_map, args.iface, args.bridge, args.interval)
    finally:
        try:
            bpf.remove_xdp(args.iface, 0)
            log(f"XDP detached from {args.iface}")
        except Exception as exc:
            log(f"[!] XDP detach failed: {exc}")


if __name__ == "__main__":
    main()
