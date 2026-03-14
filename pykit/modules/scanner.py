import ctypes
import json
import os
import shutil
import socket
import subprocess
import threading
from typing import Iterable

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn


LIB_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../core/scanner/libscanner.so",
    )
)

# Frequently scanned ports inspired by common Internet service exposure.
TOP_100_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
    32771, 9100, 1028, 7, 1029, 1040, 27352, 9999, 27017, 4899,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1024, 9, 6646,
    5051, 5901, 2717, 79, 5555, 1023, 49153, 888, 1999, 1721,
    1110, 6000, 32770, 2601, 2002, 4433, 5000, 32769, 1000, 6060,
    5550, 1130, 5902, 49157, 37, 64680, 49155, 49156, 106, 5001,
]


def _build_top_1000() -> list[int]:
    """Return 1000 deterministic common ports, extending TOP_100_PORTS with lower-range ports."""
    seen = set()
    ordered: list[int] = []

    for port in TOP_100_PORTS:
        if 1 <= port <= 65535 and port not in seen:
            ordered.append(port)
            seen.add(port)

    # Fill remaining slots with low, commonly probed port numbers.
    for port in range(1, 65536):
        if port not in seen:
            ordered.append(port)
            seen.add(port)
            if len(ordered) == 1000:
                break

    return ordered[:1000]


TOP_1000_PORTS = _build_top_1000()


def _ensure_scanner_library(verbose: bool = False) -> ctypes.CDLL:
    so_path = LIB_PATH
    c_path = os.path.join(os.path.dirname(__file__), "../../core/scanner/connect_scanner.c")

    must_rebuild = not os.path.exists(so_path)
    if not must_rebuild:
        must_rebuild = os.path.getmtime(c_path) > os.path.getmtime(so_path)

    if must_rebuild:
        print("Rebuilding scanner library...")
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

        if shutil.which("make"):
            subprocess.run(["make", "clean"], check=True, cwd=repo_root)
            subprocess.run(["make"], check=True, cwd=repo_root)
        else:
            if os.path.exists(so_path):
                os.remove(so_path)
            subprocess.run(
                [
                    "gcc",
                    "-Wall",
                    "-O2",
                    "-fPIC",
                    "-shared",
                    "-o",
                    so_path,
                    c_path,
                    "-lpthread",
                ],
                check=True,
                cwd=repo_root,
            )

    lib = ctypes.CDLL(so_path)
    if verbose:
        print(f"Loaded {so_path}")

    lib.tcp_connect_scan.argtypes = [
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_int)),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.tcp_connect_scan.restype = ctypes.c_int

    lib.scanner_free.argtypes = [ctypes.c_void_p]
    lib.scanner_free.restype = None

    return lib


def ports_for_top_n(top_ports: int) -> list[int]:
    if top_ports == 100:
        return TOP_100_PORTS[:]
    if top_ports == 1000:
        return TOP_1000_PORTS[:]
    raise ValueError("--top-ports supports only 100 or 1000")


def _chunk_consecutive_ports(ports: Iterable[int]) -> list[tuple[int, int]]:
    ordered = sorted(set(ports))
    if not ordered:
        return []

    chunks: list[tuple[int, int]] = []
    start = prev = ordered[0]
    for port in ordered[1:]:
        if port == prev + 1:
            prev = port
            continue
        chunks.append((start, prev))
        start = prev = port
    chunks.append((start, prev))
    return chunks


# Python wrapper function
def fast_scan(
    target: str,
    start_port: int = 1,
    end_port: int = 1024,
    timeout: int = 4,
    threads: int = 256,
    verbose: bool = False,
) -> list[int]:
    """Scan a target for open TCP ports using the C multithreaded scanner."""
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        raise ValueError("Invalid port range. Use 1-65535 and ensure start <= end.")
    if (end_port - start_port + 1) > 65536:
        raise ValueError("Range too large, max 65536 ports allowed")
    if timeout < 1:
        raise ValueError("Timeout must be at least 1 second")
    if threads < 1 or threads > 1024:
        raise ValueError("Threads must be between 1 and 1024")

    try:
        addr_info = socket.getaddrinfo(target, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        family, _, _, _, sockaddr = addr_info[0]
        ip = sockaddr[0]
        if verbose:
            print(f"Resolved {target} -> {ip}")
        target = ip
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname: {target}") from exc

    lib = _ensure_scanner_library(verbose=verbose)

    ports_ptr = ctypes.POINTER(ctypes.c_int)()
    count = ctypes.c_int(0)
    progress_counter = ctypes.c_int(0)
    total_ports = end_port - start_port + 1

    result: dict[str, int] = {"ret": -1}

    def _run_scan() -> None:
        if verbose:
            print(f"Calling tcp_connect_scan with family={family}")
        result["ret"] = lib.tcp_connect_scan(
            target.encode("utf-8"),
            start_port,
            end_port,
            family,
            timeout,
            threads,
            ctypes.byref(ports_ptr),
            ctypes.byref(count),
            ctypes.byref(progress_counter),
        )

    scan_thread = threading.Thread(target=_run_scan, daemon=True)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} ports checked"),
        transient=True,
    ) as progress:
        task_id = progress.add_task(f"Scanning {target} {start_port}-{end_port}...", total=total_ports)
        scan_thread.start()

        while scan_thread.is_alive():
            progress.update(task_id, completed=min(progress_counter.value, total_ports))
            scan_thread.join(timeout=0.1)

        progress.update(task_id, completed=total_ports)

    ret = result["ret"]
    if ret != 0:
        message = {
            -1: "Memory allocation or thread creation failed",
        }.get(ret, f"Unknown error (code {ret})")
        raise RuntimeError(message)

    if verbose:
        print(f"Found {count.value} open ports")

    open_ports = [ports_ptr[i] for i in range(count.value)]

    if ports_ptr:
        lib.scanner_free(ctypes.cast(ports_ptr, ctypes.c_void_p))

    return sorted(set(open_ports))


def fast_scan_ports(
    target: str,
    ports: list[int],
    timeout: int = 4,
    threads: int = 256,
    verbose: bool = False,
) -> list[int]:
    """Scan an arbitrary list of ports by grouping contiguous runs for efficient C calls."""
    open_ports: list[int] = []
    for start, end in _chunk_consecutive_ports(ports):
        open_ports.extend(
            fast_scan(
                target,
                start_port=start,
                end_port=end,
                timeout=timeout,
                threads=threads,
                verbose=verbose,
            )
        )
    return sorted(set(open_ports))


def build_json_result(target: str, ports: list[int], duration: float) -> str:
    payload = {
        "target": target,
        "ports": sorted(ports),
        "count": len(ports),
        "duration": duration,
    }
    return json.dumps(payload)
