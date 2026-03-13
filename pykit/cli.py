import typer

from pykit.modules.scanner import fast_scan

app = typer.Typer(help="offkit command-line tools")


@app.callback()
def main() -> None:
    """offkit CLI entrypoint."""


@app.command()
def scan(target: str, start: int = 1, end: int = 1024) -> None:
    """Run a TCP connect scan against TARGET from START to END ports."""
    ports = fast_scan(target, start, end)
    print(f"Open ports on {target}: {ports}")


if __name__ == "__main__":
    app()
