# pykit/cli.py
import typer
from pykit.modules.scanner import fast_scan

app = typer.Typer()

@app.command()
def scan(target: str, start: int = 1, end: int = 1024):
    ports = fast_scan(target, start, end)
    print(f"Open ports on {target}: {ports}")

if __name__ == "__main__":
    app()
