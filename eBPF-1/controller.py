#!/usr/bin/env python3
import argparse
import glob
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time

STATUS_ALLOWED = 1
VLAN_MAX = 4094
FDB_RETRIES = 30
MAP_NAME = "auth_map"
XDP_SECTION = "xdp"
MAP_MISS_LIMIT = 5

running = True


def log(msg):
    print(f"[controller] {msg}", flush=True)


def stop_handler(_signum, _frame):
    global running
    running = False


def parse_args():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="802.1X/RADIUS enforcement controller (no-BCC): clang + iproute2 XDP attach + bpftool map polling")
    parser.add_argument("--iface", default="eth0",
                        help="XDP attachment interface and uplink toward CE2 (default: eth0)")
    parser.add_argument("--bridge", default="bridge0",
                        help="vlan-filtering bridge device (default: bridge0)")
    parser.add_argument("--source", default=os.path.join(script_dir, "radius_xdp.c"),
                        help="path to the eBPF C source (default: radius_xdp.c next to this script)")
    parser.add_argument("--object", default=os.path.join(script_dir, "radius_xdp.o"),
                        help="path to the compiled eBPF object (default: radius_xdp.o next to this script)")
    parser.add_argument("--clang", default="clang",
                        help="clang binary used to compile the XDP object (default: clang)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="auth_map poll interval in seconds (default: 1.0)")
    return parser.parse_args()


def check_root():
    if os.geteuid() != 0:
        sys.exit("[!] this daemon must run as root inside the eBPF-1 node")


def check_binaries():
    for binary in ("ip", "bpftool", "ebtables", "bridge"):
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


MULTIARCH_MAP = {
    "x86_64": "x86_64-linux-gnu",
    "i386": "i386-linux-gnu",
    "i686": "i386-linux-gnu",
    "aarch64": "aarch64-linux-gnu",
    "armv6l": "arm-linux-gnueabihf",
    "armv7l": "arm-linux-gnueabihf",
    "riscv64": "riscv64-linux-gnu",
    "ppc64le": "powerpc64le-linux-gnu",
    "s390x": "s390x-linux-gnu",
}


def kernel_include_flags():
    if os.path.isfile("/usr/include/asm/types.h"):
        return []
    triple = MULTIARCH_MAP.get(platform.machine())
    candidates = [f"/usr/include/{triple}"] if triple else []
    try:
        proc = subprocess.run(["gcc", "-print-multiarch"], capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            candidates.append("/usr/include/" + proc.stdout.strip())
    except FileNotFoundError:
        pass
    for cand in candidates:
        if cand and os.path.isfile(os.path.join(cand, "asm", "types.h")):
            return ["-I", cand]
    for found in sorted(glob.glob("/usr/include/*/asm/types.h")):
        return ["-I", os.path.dirname(os.path.dirname(found))]
    return []


def ensure_object(args):
    obj = args.object
    src = args.source
    if not os.path.isfile(obj):
        if not os.path.isfile(src):
            sys.exit(f"[!] BPF source not found: {src} (and no prebuilt object at {obj})")
    elif not os.path.isfile(src) or os.path.getmtime(src) <= os.path.getmtime(obj):
        return obj
    clang = shutil.which(args.clang)
    if clang is None:
        if os.path.isfile(obj):
            log(f"[!] clang not found; using existing (possibly stale) {obj}")
            return obj
        sys.exit(f"[!] clang ({args.clang}) not found and no prebuilt object at {obj}")
    log(f"[*] compiling {src} -> {obj}")
    cmd_base = [clang, "-O2", "-target", "bpf", "-c", src, "-o", obj]
    rc = run_cmd(cmd_base)
    if rc != 0:
        extra = kernel_include_flags()
        if extra:
            log(f"[*] retry with include dir {extra[1]}")
            rc = run_cmd(cmd_base + extra)
    if rc != 0:
        if os.path.isfile(obj):
            log(f"[!] compilation failed; using existing (possibly stale) {obj}")
            return obj
        sys.exit("[!] eBPF compilation failed: verificare che i kernel headers UAPI siano "
                 "presenti (asm/types.h: serve il pacchetto linux-libc-dev o -I/usr/include/"
                 "<multiarch>) oppure copiare nel nodo radius_xdp.o precompilato (vedi guida §2.2)")
    log(f"[*] compiled OK -> {obj}")
    return obj


def attach_xdp(iface, obj):
    for mode, quiet in (("xdp", True), ("xdpgeneric", False)):
        if run_cmd(["ip", "link", "set", "dev", iface, mode, "obj", obj, "sec", XDP_SECTION],
                   quiet=quiet) == 0:
            return mode
    sys.exit(f"[!] XDP attach to {iface} failed (native and generic); "
             f"if another XDP program is attached run: ip link set dev {iface} xdp off")


def detach_xdp(iface, mode):
    if run_cmd(["ip", "link", "set", "dev", iface, mode, "off"]) != 0:
        log(f"[!] XDP detach failed on {iface}")
    else:
        log(f"XDP detached from {iface}")


def _num(value):
    if isinstance(value, int):
        return value
    text = str(value)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def list_auth_map_ids():
    try:
        proc = subprocess.run(["bpftool", "-j", "map", "show"], capture_output=True, text=True)
    except FileNotFoundError:
        return []
    if proc.returncode != 0:
        return []
    try:
        maps = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(maps, list):
        return []
    return [m["id"] for m in maps
            if isinstance(m, dict) and str(m.get("name", "")).startswith(MAP_NAME)]


def mac_from_key(key):
    if isinstance(key, dict):
        raw = key.get("addr")
        if raw is None:
            raw = key.get("mac", key.get("mac_addr", key.get("key")))
        if raw is None:
            raw = [v for field in key.values() if isinstance(field, list) for v in field]
    else:
        raw = key
    if not isinstance(raw, (list, tuple)) or len(raw) < 6:
        raise ValueError(f"bad map key: {key!r}")
    return ":".join(f"{_num(b) & 0xFF:02x}" for b in raw[:6])


def value_fields(value, key):
    if isinstance(value, dict):
        return _num(value.get("vlan_id", 0)), _num(value.get("status", 0))
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"bad map value for {key}: {value!r}")
    raw = bytes(_num(b) & 0xFF for b in value)
    if len(raw) < 11:
        raise ValueError(f"map value too short for {key}: {len(raw)} bytes")
    return int.from_bytes(raw[0:4], "little"), raw[10]


def dump_map(map_id):
    try:
        proc = subprocess.run(["bpftool", "-j", "map", "dump", "id", str(map_id)],
                              capture_output=True, text=True)
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    try:
        entries = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(entries, list):
        return None
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            mac = mac_from_key(entry.get("key"))
            vlan, status = value_fields(entry.get("value"), mac)
        except Exception as exc:
            log(f"[!] skipping malformed auth entry: {exc}")
            continue
        out.append((mac, vlan, status))
    return out


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


def poll_loop(map_id, iface, bridge, interval):
    known = {}
    pending = {}
    misses = 0
    while running:
        entries = dump_map(map_id)
        if entries is None:
            misses += 1
            if misses >= MAP_MISS_LIMIT:
                log(f"[!] auth_map id {map_id} unreadable, re-resolving")
                ids = list_auth_map_ids()
                if ids and map_id not in ids:
                    map_id = ids[0]
                    log(f"[*] switched to auth_map id {map_id}")
                    misses = 0
        else:
            misses = 0
            for mac, vlan, status in entries:
                if status != STATUS_ALLOWED or not 1 <= vlan <= VLAN_MAX:
                    continue
                if known.get(mac) == vlan:
                    continue
                if mac not in pending:
                    log(f"[*] authenticated: mac={mac} vlan={vlan}")
                    pending[mac] = [vlan, 0]
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
    obj = ensure_object(args)

    before = set(list_auth_map_ids())
    mode = attach_xdp(args.iface, obj)

    ids = [i for i in list_auth_map_ids() if i not in before] or list_auth_map_ids()
    if not ids:
        detach_xdp(args.iface, mode)
        sys.exit(f"[!] auth_map not found after attaching XDP to {args.iface}")
    map_id = ids[0]
    log(f"attached XDP to {args.iface} ({mode}); auth_map id {map_id}; "
        f"polling every {args.interval}s (CTRL+C to detach)")

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    try:
        poll_loop(map_id, args.iface, args.bridge, args.interval)
    finally:
        detach_xdp(args.iface, mode)


if __name__ == "__main__":
    main()
