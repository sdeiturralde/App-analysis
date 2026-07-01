# Flask Vulnerability Scanner

A lightweight static analysis tool that scans Python Flask applications for common security vulnerabilities using Python’s **Abstract Syntax Tree (AST)** module.  
Designed for educational purposes and basic security audits.


## How It Works

1. **Parses** the source code into an Abstract Syntax Tree using `ast.parse()`.
2. **Traverses** the tree with a custom `NodeVisitor` that overrides `visit_Call`, `visit_Assign`, and `visit_Return`.
3. **Analyzes** each node for dangerous patterns:
   - `conn.execute(...)` with dynamic strings → SQL Injection
   - `send_file(...)` with user-controlled path → Path Traversal (download)
   - `f.save(...)` with `f.filename` → Path Traversal (upload)
   - `return f"...{var}..."` where `var` comes from `request.args` → XSS
   - Variable assignments like `API_KEY = "..."` → Hardcoded secret
   - `app.config['DEBUG'] = True` → Debug mode
4. Uses **taint‑heuristics** – tracks variable names like `query`, `filename`, etc., to catch data flows even when stored in variables.
5. **Reports** all findings with severity, line number, and remediation advice.

## Usage
```bash
python scanner.py path/to/your_app.py
```

## Limitations
This tool is a static heuristic analyzer – it does not execute the code.
As a result, it may produce:

**False positives** – variables with common names (e.g., filepath) that are actually safe.

**False negatives** – tainted data stored in variables not in the suspicious list (e.g., my_var).

## Results
<img src="https://raw.githubusercontent.com/sdeiturralde/App-analysis/refs/heads/main/imgs/8.png"/>
