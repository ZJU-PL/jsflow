"""
Vulnerability Detection - Security analysis and pattern matching.

This package handles the detection of security vulnerabilities by analyzing
data flow paths in the object property graph.

Modules:
--------
- vul_checking: Main vulnerability detection engine
- vul_func_lists: Sink function signatures by vulnerability type

Detection Process:
------------------
1. Find sink function calls in the graph
2. Trace back data flow via OBJ_REACHES edges
3. Apply trace rules to filter candidate paths
4. Validate paths for user input and sanitization
5. Report confirmed vulnerabilities

Supported Vulnerabilities:
-------------------------
- OS Command Injection (CWE-78)
- Cross-Site Scripting (CWE-79)
- Code Execution (CWE-94)
- Prototype Pollution (CWE-1321)
- Path Traversal (CWE-22)
- NoSQL Injection (CWE-943)
"""
