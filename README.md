# offkit

A hybrid C + Python offensive security toolkit focused on speed and extensibility.

**Current MVP feature:**  
Multi-threaded TCP connect port scanner (faster than naive Python scripts, with native C performance).

### Features
- Multi-threaded port scanning via C sockets + pthreads
- Hostname resolution (IPv4/IPv6)
- Deterministic scanner rebuild behavior when C sources change
- Tunable timeout and thread count
- Built-in top-port profiles (100 and 1000)
- Optional JSON/output-file reporting
- Rich progress feedback during scans

### Installation (editable/development mode)

```bash
git clone https://github.com/yourusername/offkit.git
cd offkit
python -m venv venv
source venv/bin/activate
pip install -e .
```

### Quick Usage
Scan a target (replace with your own or scanme.nmap.org for testing)
```bash
python -m pykit.cli scan scanme.nmap.org --start 1 --end 200
```

Scan top common ports with custom timeout/threads:
```bash
offkit scan scanme.nmap.org --top-ports 100 --timeout 2 --threads 512
```

Write output to a file:
```bash
offkit scan 127.0.0.1 --start 1 --end 1000 --output open_ports.txt
```

JSON output for scripting:
```bash
offkit scan scanme.nmap.org --top-ports 1000 --json
```

Show built-in top-port sets:
```bash
offkit top-ports
```
