import time
from pathlib import Path

import typer

from pykit.modules.scanner import (
    TOP_1000_PORTS,
    TOP_100_PORTS,
    build_json_result,
    fast_scan,
    fast_scan_ports,
    ports_for_top_n,
)

app = typer.Typer(help="offkit command-line tools")


@app.callback()
def main() -> None:
    """offkit CLI entrypoint."""


@app.command()
def scan(
    target: str,
    start: int = typer.Option(1, help="Start of port range."),
    end: int = typer.Option(1024, help="End of port range."),
    top_ports: int | None = typer.Option(None, "--top-ports", help="Scan top 100 or 1000 ports."),
    timeout: int = typer.Option(4, "--timeout", help="Socket timeout in seconds."),
    output: Path | None = typer.Option(None, "--output", help="Write open ports to FILE."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
    threads: int = typer.Option(256, "--threads", min=1, max=1024, help="Worker thread count (1-1024)."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON result payload."),
) -> None:
    """Run a TCP connect scan against TARGET."""
    start_time = time.perf_counter()

    if top_ports is not None:
        selected_ports = ports_for_top_n(top_ports)
        typer.echo(f"Scanning built-in top {top_ports} ports set")
        ports = fast_scan_ports(
            target,
            selected_ports,
            timeout=timeout,
            threads=threads,
            verbose=verbose,
        )
    else:
        ports = fast_scan(
            target,
            start_port=start,
            end_port=end,
            timeout=timeout,
            threads=threads,
            verbose=verbose,
        )

    duration = round(time.perf_counter() - start_time, 3)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        sorted_ports = sorted(ports)
        output.write_text("\n".join(str(port) for port in sorted_ports) + ("\n" if sorted_ports else ""))
        typer.echo(f"Saved {len(sorted_ports)} ports to {output}")
        if json_output:
            typer.echo(build_json_result(target, sorted_ports, duration))
        return

    if json_output:
        typer.echo(build_json_result(target, ports, duration))
        return

    typer.echo(f"Open ports on {target}: {ports}")
    typer.echo(f"Found {len(ports)} open ports in {duration:.3f}s")


@app.command("top-ports")
def top_ports_command() -> None:
    """Print the built-in top port sets used by --top-ports."""
    typer.echo("Top 100 ports:")
    for idx, port in enumerate(TOP_100_PORTS, start=1):
        typer.echo(f"{idx:>4}. {port}")

    typer.echo("\nTop 1000 ports:")
    for idx, port in enumerate(TOP_1000_PORTS, start=1):
        typer.echo(f"{idx:>4}. {port}")


if __name__ == "__main__":
    app()
