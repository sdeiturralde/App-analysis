"""
Simple vulnerability scanner for Flask/Python code.
Uses AST analysis + basic taint heuristics (variable name checks).
"""

#######################################
# #       Import Libraries        # #
#######################################

import ast #Abstract Syntax Treem it allows us to parse Python source code into an interactive tree structure
import sys


#######################################
# #             Variables           # #
#######################################

# Common variable names that often hold user-controlled data
SUSPICIOUS_NAMES = {'filename', 'filepath', 'query', 'q', 'name', 'user', 'input'}


#######################################
# #              Clases             # #
#######################################

# Simple vulnerability ranking
class Vulnerability:
    def __init__(self, severity, title, line, fix):
        self.severity = severity
        self.title = title
        self.line = line
        self.fix = fix

    def __str__(self):
        return f"[{self.severity}] {self.title} (line {self.line})\n    Fix: {self.fix}\n"


# Class that use the ats library that we just imported to dive into the python code
class SimpleScanner(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.vulns = []

    # Tells the scanner to continue traversing inside the function body when we call it.
    def visit_FunctionDef(self, node):
        self.generic_visit(node)

    # Check function calls
    def visit_Call(self, node):
        """ SQL Injection: looks for .execute() calls where the first argument is an f-string,
        a concatenation, or a string containing %s/{}"""
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            if node.args and self._is_unsafe_query(node.args[0]):
                self.vulns.append(Vulnerability(
                    "Critical",
                    "SQL Injection",
                    node.lineno,
                    "Use parameterized queries with ? placeholders."
                ))

        """ Path Traversal in download: finds send_file() calls and it checks if the argument
        contains tainted input"""
        if isinstance(node.func, ast.Name) and node.func.id == 'send_file':
            #This is where it checks it
            if node.args and self._contains_tainted_input(node.args[0]):
                self.vulns.append(Vulnerability(
                    "Critical",
                    "Path Traversal in File Download",
                    node.lineno,
                    "Use os.path.basename() and validate final path."
                ))

        # Path Traversal in upload: Does the same but with the .save() files
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'save':
            if node.args and self._contains_tainted_input(node.args[0]):
                self.vulns.append(Vulnerability(
                    "Critical",
                    "Path Traversal in File Upload",
                    node.lineno,
                    "Use secure_filename() from werkzeug.utils."
                ))

        self.generic_visit(node)

    # Check assignments
    def visit_Assign(self, node):
        # Hardcoded secrets: check if a variable with common secret names is assigned a string literal
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if var_name in ('API_KEY', 'SECRET_TOKEN', 'SECRET_KEY', 'PASSWORD'):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.vulns.append(Vulnerability(
                            "Medium",
                            f"Hardcoded secret '{var_name}'",
                            node.lineno,
                            "Store in environment variables using os.getenv()."
                        ))

        # Debug mode
        # In AST, app.config['DEBUG'] is a Subscript, not an Attribute.
        if isinstance(node.targets[0], ast.Subscript):
            subscript = node.targets[0]
            # Check if the object is app.config
            if isinstance(subscript.value, ast.Attribute):
                if subscript.value.attr == 'config' and isinstance(subscript.value.value, ast.Name) and subscript.value.value.id == 'app':
                    # Check if the slice key is 'DEBUG'
                    if isinstance(subscript.slice, ast.Index) and isinstance(subscript.slice.value, ast.Constant):
                        if subscript.slice.value.value == 'DEBUG':
                            #check if app.config['DEBUG'] = True
                            if isinstance(node.value, ast.Constant) and node.value.value is True:
                                self.vulns.append(Vulnerability(
                                    "Medium",
                                    "Debug mode enabled",
                                    node.lineno,
                                    "Set DEBUG=False in production."
                                ))

        self.generic_visit(node)

    # Check return statements for XSS
    def visit_Return(self, node):
        if node.value and isinstance(node.value, ast.JoinedStr):
            """If a return statement contains an f-string return check 
            if it contains tainted data"""
            if self._contains_tainted_input(node.value):
                self.vulns.append(Vulnerability(
                    "High",
                    "Reflected XSS",
                    node.lineno,
                    "Escape output with markupsafe.escape() or use a template engine."
                ))
        self.generic_visit(node)

    # Helper: checks if that piece of code contains data that originally came from an user
    def _contains_tainted_input(self, node):
        """Return True if the node references request.args, request.form,
        request.files, f.filename, or a variable with a suspicious name.
        """
        for child in ast.walk(node):
            # Direct reference to request.args/form/files
            if isinstance(child, ast.Attribute) and child.attr in ('args', 'form', 'files'):
                if isinstance(child.value, ast.Name) and child.value.id == 'request':
                    return True
            # Direct reference to f.filename (file upload)
            if isinstance(child, ast.Attribute) and child.attr == 'filename':
                if isinstance(child.value, ast.Name) and child.value.id == 'f':
                    return True
            # Reference to a variable with a suspicious name (heuristic)
            if isinstance(child, ast.Name) and child.id in SUSPICIOUS_NAMES:
                return True
        return False

    """Helper: Check if the SQL query string is built dynamically isntead of using
    safe parameterized queries"""
    def _is_unsafe_query(self, node):
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if '%s' in node.value or '{}' in node.value:
                return True
        return False

    # Print results
    def report(self):
        if not self.vulns:
            print("No vulnerabilities found.")
            return
        print(f"\n--- Vulnerabilities in {self.filename} ---\n")
        for v in self.vulns:
            print(v)
        print(f"Total: {len(self.vulns)}")


#######################################
# #             Functions          # #
#######################################

"""Wrap up function. With this function we open the file, reading the source code,
parsing it into AST and we run the scanner"""
def scan_file(filename):
    with open(filename, 'r') as f:
        code = f.read()
    tree = ast.parse(code)
    scanner = SimpleScanner(filename)
    scanner.visit(tree)
    scanner.report()


#######################################
# #              Main               # #
#######################################

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <python_file>")
        sys.exit(1)
    scan_file(sys.argv[1])