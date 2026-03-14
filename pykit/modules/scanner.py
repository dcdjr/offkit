import ctypes
import ctypes.util
import os
import socket
import subprocess
import shutil

from rich.progress import Progress, SpinnerColumn, TextColumn


LIB_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../core/scanner/libscanner.so",
    )
)


def _ensure_scanner_library() -> ctypes.CDLL:
    if not os.path.exists(LIB_PATH):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
        if shutil.which("make"):
            subprocess.run(["make"], check=True, cwd=repo_root)
        else:
            subprocess.run(
                [
                    "gcc",
                    "-Wall",
                    "-Werror",
                    "-O2",
                    "-fPIC",
                    "-shared",
                    "-o",
                    os.path.join(repo_root, "core/scanner/libscanner.so"),
                    os.path.join(repo_root, "core/scanner/connect_scanner.c"),
                    "-lpthread",
                ],
                check=True,
                cwd=repo_root,
            )

    lib = ctypes.CDLL(LIB_PATH)
    lib.tcp_connect_scan.argtypes = [
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_int)),
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.tcp_connect_scan.restype = ctypes.c_int

    lib.scanner_free.argtypes = [ctypes.c_void_p]
    lib.scanner_free.restype = None

    return lib


# Python wrapper function
def fast_scan(target: str, start_port: int = 1, end_port: int = 1024) -> list[int]:
    """
    Scan target host for open TCP ports using the C multi-threaded scanner.
    Returns sorted list of open ports.
    """
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        raise ValueError("Invalid port range. Use 1-65535 and ensure start <= end.")

    try:
        addr_info = socket.getaddrinfo(target, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        family, _, _, _, sockaddr = addr_info[0]
        ip = sockaddr[0]
        print(f"Resolved {target} -> {ip}")
        target = ip
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname: {target}") from exc

    lib = _ensure_scanner_library()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(f"Scanning {target} {start_port}-{end_port}...", total=None)

        # Prepare output variables
        ports_ptr = ctypes.POINTER(ctypes.c_int)()
        count = ctypes.c_int(0)

        # Call the C function
        ret = lib.tcp_connect_scan(
            target.encode("utf-8"),
            start_port,
            end_port,
            family,
            ctypes.byref(ports_ptr),
            ctypes.byref(count),
        )

    if ret != 0:
        raise RuntimeError(f"C scan failed with return code {ret}")

    # Convert C array to Python list
    open_ports = [ports_ptr[i] for i in range(count.value)]

    # Free the C-allocated array to prevent leak
    lib.scanner_free(ports_ptr);

    # Sort and remove possible duplicates
    return sorted(set(open_ports))
