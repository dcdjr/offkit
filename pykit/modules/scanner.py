import ctypes
import ctypes.util
import os
import socket
import subprocess

from rich.progress import Progress, SpinnerColumn, TextColumn


LIB_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../core/scanner/libscanner.so",
    )
)


def _ensure_scanner_library() -> ctypes.CDLL:
    if not os.path.exists(LIB_PATH):
        subprocess.run(["make"], check=True, cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

    lib = ctypes.CDLL(LIB_PATH)
    lib.tcp_connect_scan.argtypes = [
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_int)),
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.tcp_connect_scan.restype = ctypes.c_int
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
        ip = socket.gethostbyname(target)  # resolves hostname
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
        task = progress.add_task(
            f"Scanning {target} {start_port}-{end_port}...",
            total=end_port - start_port + 1,
        )

        # Prepare output variables
        ports_ptr = ctypes.POINTER(ctypes.c_int)()
        count = ctypes.c_int(0)

        # Call the C function
        ret = lib.tcp_connect_scan(
            target.encode("utf-8"),
            start_port,
            end_port,
            ctypes.byref(ports_ptr),
            ctypes.byref(count),
        )

        progress.update(task, completed=end_port - start_port + 1)

    if ret != 0:
        raise RuntimeError(f"C scan failed with return code {ret}")

    # Convert C array to Python list
    open_ports = [ports_ptr[i] for i in range(count.value)]

    # Free the C-allocated array to prevent leak
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    libc.free.argtypes = [ctypes.c_void_p]
    libc.free(ports_ptr)

    # Sort and remove possible duplicates
    return sorted(set(open_ports))
