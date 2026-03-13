# offkit

A hybrid C + Python offensive security toolkit focused on speed and extensibility.

**Current MVP feature:**  
Multi-threaded TCP connect port scanner (faster than naive Python scripts, with native C performance).

### Features
- Multi-threaded port scanning via C sockets + pthreads
- Hostname resolution
- Memory-safe
- Basic rich progress feedback during scans
- Easy Python wrapper via ctypes

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

Or from inside venv:
```bash
offkit scan 127.0.0.1 --start 1 --end 1000
```
