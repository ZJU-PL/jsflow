# probejs Taint Analysis Benchmark Suite

**Micro-Benchmarks for Evaluating JavaScript Taint Bug Detection Precision and Recall**

This benchmark suite provides test cases for evaluating static analysis tools' ability to detect JavaScript taint-related vulnerabilities supported by probejs.

## Overview

This benchmark suite is designed to:

- **Evaluate Precision**: Test cases marked as `SAFE` should NOT trigger false positives
- **Evaluate Recall**: Test cases marked as `VULNERABLE` should be detected
- **Test Complex Flows**: Taint propagation through functions, objects, arrays, closures, async patterns
- **Cover Real-World Scenarios**: Patterns inspired by CVEs, production code, and common anti-patterns
- **Validate Framework Integration**: Express.js, Next.js, MongoDB, PostgreSQL, MySQL, and more

## Structure

```
tests/regress/
├── BENCHMARK_METADATA_V3.json          # Metadata and test categorization
├── evaluate_benchmark.js              # Evaluation framework
├── README_BENCHMARK.md                # Documentation
├── vulnerability_detection/           # Main vulnerability test files
│   ├── xss_vulnerable.js              # XSS vulnerable tests
│   ├── xss_comprehensive.js           # Comprehensive XSS (CWE-79)
│   ├── os_command_injection.js        # OS command injection
│   ├── os_command_injection_comprehensive.js # Comprehensive OS command injection (CWE-78)
│   ├── code_execution.js              # Code execution
│   ├── code_execution_comprehensive.js # Comprehensive code execution (CWE-94)
│   ├── path_traversal.js              # Path traversal
│   ├── path_traversal_comprehensive.js # Comprehensive path traversal (CWE-22)
│   ├── nosql_injection.js             # NoSQL injection (CWE-943)
│   └── prototype_pollution.js         # Prototype pollution (CWE-1321)
├── precision/                         # Precision-only tests (safe patterns)
│   ├── precision_context.js
│   ├── precision_flow.js
│   ├── precision_field.js
│   ├── precision_path.js
│   ├── precision_traps.js
│   ├── xss_safe.js
│   ├── path_traversal_safe.js
│   ├── os_command_safe.js
│   └── sanitization.js
├── recall/                            # Recall-focused tests
│   ├── recall_crypto.js
│   ├── recall_data_structures.js
│   ├── recall_fs_process.js
│   ├── recall_http_misc.js
│   ├── recall_network.js
│   ├── recall_vm_timers.js
│   └── recall_worker_cluster.js
└── flows/                             # Complex / async flow tests
    ├── complex_flows.js
    ├── async_bench.js
    └── motivating_v3.js
```

## CWE Coverage

| CWE ID | Vulnerability Type | Test Files | Function Count |
|---------|-------------------|-------------|----------------|
| CWE-78 | OS Command Injection | os_command_injection.js, os_command_injection_comprehensive.js | ~70 |
| CWE-79 | Cross-Site Scripting (XSS) | xss_vulnerable.js, precision/xss_safe.js, xss_comprehensive.js | ~130 |
| CWE-94 | Code Execution | code_execution.js, code_execution_comprehensive.js | ~40 |
| CWE-22 | Path Traversal | path_traversal.js, precision/path_traversal_safe.js, path_traversal_comprehensive.js | ~50 |
| CWE-943 | NoSQL Injection | nosql_injection.js | ~25 |
| CWE-1321 | Prototype Pollution | prototype_pollution.js | ~20 |

**Total**: ~335 test functions across 6 CWE categories supported by probejs

## Test Categories

### 1. Vulnerability Detection (Recall Tests)

Tests marked with `// VULNERABLE` contain actual security vulnerabilities that should be detected by static analysis tools.

#### 1.1 OS Command Injection (CWE-78)

- **All child_process functions**: exec, execSync, execFile, execFileSync, spawn, spawnSync, fork
- **Command Separators**: ;, &&, ||, |, &, \n
- **Meta-Characters**: Backticks, $(), variable substitution, wildcards, globbing
- **Real-World Patterns**:
  - File upload processing
  - Image/video processing (ImageMagick, FFmpeg)
  - PDF generation
  - Network diagnostics (ping, nslookup)
  - Backup and cron operations
- **Advanced Attacks**: Blind injection, OOB exfiltration, reverse shells, base64/hex encoding

#### 1.2 Cross-Site Scripting (XSS) (CWE-79)

- **XSS Types**:
  - Reflected XSS
  - Stored XSS
  - DOM-based XSS
- **Contexts**: HTML body, attributes, JavaScript strings, URLs, CSS
- **Injection Points**:
  - Direct concatenation
  - Template literals
  - Event handlers
  - src/href attributes
  - innerHTML, document.write, eval, setTimeout
- **Filter Evasion**: Case variation, encoding, tag closure, comments, null bytes
- **Framework-Specific**: Express.js, Next.js, React dangerouslySetInnerHTML
- **Advanced Techniques**:
  - localStorage/sessionStorage
  - URL fragments
  - postMessage
  - WebSockets
  - JSONP callbacks
  - Clickjacking
  - SVG, data URIs

#### 1.3 Code Execution (CWE-94)

- **Execution Methods**:
  - eval() with user input
  - Function() constructor
  - setTimeout/setInterval with string arguments
  - setImmediate
  - Node.js VM module (runInContext, runInNewContext)
  - Dynamic require()
  - Global object pollution

#### 1.4 Path Traversal (CWE-22)

- **Traversal Patterns**: ../, URL encoding, double encoding, UTF-8 encoding
- **Path Manipulation**: Null byte injection, absolute paths, long paths
- **Real-World Scenarios**:
  - File downloads
  - Avatar/image uploads
  - Backup restoration
  - Configuration file access

#### 1.5 NoSQL Injection (CWE-943)

- **MongoDB Patterns**:
  - Direct object injection
  - $ne, $gt, $lt operators
  - Regex-based injection
- **Mongoose Patterns**: Query building, field manipulation

#### 1.6 Prototype Pollution (CWE-1321)

- **Vulnerable Patterns**:
  - Recursive merge functions
  - Constructor prototype pollution
  - Lodash-like set() operations
  - JSON.parse with dangerous keys
- **Safe Patterns**:
  - Denylist validation
  - Object.create(null)
  - Map usage

### 2. Precision Tests

Tests marked with `// SAFE` contain no actual vulnerabilities. Analysis tools should NOT report false positives.

#### 2.1 Precision Categories

- **Context Sensitivity**: Handling variables in different calling contexts
- **Flow Sensitivity**: Respecting operation order and variable updates
- **Field Sensitivity**: Tracking individual object properties separately
- **Path Sensitivity**: Distinguishing different array/object paths
- **Trap Cases**: Edge cases and anti-patterns that confuse analysis

#### 2.2 Safe Patterns

- **XSS**: textContent, HTML entity encoding, template engine auto-escaping
- **Command Injection**: Array form of spawn/execFile, argument validation, shell escaping
- **Path Traversal**: Path normalization, whitelisting, absolute path validation

### 3. Complex Flow Tests

Tests that challenge taint analysis through complex data flow patterns:

- **Closure Variables**: Taint captured in closures
- **Promises/Async/Await**: Taint through Promise chains
- **Object Property Access**: Flow through this, prototypes, computed properties
- **Array Operations**: map, filter, reduce, forEach
- **Destructuring and Spread**: Taint in destructuring assignments
- **Generators and Iterators**: Taint through generator yields
- **Mixed Callback/Promise**: Taint surviving between callback and promise patterns

### 4. Recall Tests

Tests focused on detecting vulnerabilities through specific Node.js module patterns:

- **Data Structures**: Arrays, objects, Maps, Sets
- **File Operations**: fs.readFile, fs.writeFile, fs.unlink, etc.
- **HTTP Operations**: http.get, https.request, axios, fetch
- **Crypto Operations**: crypto.createHash, crypto.createCipher, etc.
- **VM and Timers**: vm.runInContext, setTimeout, setInterval
- **Worker/Cluster**: fork, cluster.fork
- **Network Operations**: net, dgram, tls modules

## Evaluation Framework

### Running Evaluation

```bash
# Basic evaluation (requires tool output in JSON format)
node tests/regress/evaluate_benchmark.js tests/regress/ tool_output.json

# The evaluation framework will:
# 1. Parse test files and metadata
# 2. Compare tool results against expected behavior
# 3. Calculate precision, recall, and F1 score
# 4. Generate detailed report by CWE
```

### Metrics

The evaluation framework calculates:

- **True Positives (TP)**: Vulnerabilities correctly detected
- **False Positives (FP)**: Safe code incorrectly flagged
- **True Negatives (TN)**: Safe code correctly not flagged
- **False Negatives (FN)**: Vulnerabilities not detected

**Calculated Metrics**:
- **Precision** = TP / (TP + FP) - How many findings are actual vulnerabilities
- **Recall** = TP / (TP + FN) - How many vulnerabilities were found
- **F1 Score** = 2 × (Precision × Recall) / (Precision + Recall) - Harmonic mean of precision and recall

## Metadata System

`BENCHMARK_METADATA_V3.json` provides:

- **CWE Mapping**: Test files organized by CWE
- **Function Metadata**: Expected behavior for each test function
- **Test Categorization**: Vulnerability detection, precision, recall, complex flows
- **Statistics**: Total counts, coverage information

### Annotation Format

Test functions use inline comments to specify expected behavior:

```javascript
// VULNERABLE: This function contains a vulnerability and should be detected
function vulnerableFunction(req) {
    eval(req.query.code);
}

// SAFE: This function is secure and should NOT trigger false positives
function safeFunction(req) {
    setTimeout(() => console.log(req.query.code), 1000);
}
```

## Contributing

### Adding New Tests

1. **Create Test Function** in appropriate file or new test file:
   ```javascript
   // VULNERABLE or SAFE: Description of what's being tested
   function myNewTest(req) {
       // Test implementation
   }
   ```

2. **Export Function**: Add to module.exports
   ```javascript
   module.exports = {
       existingFunction,
       myNewTest
   };
   ```

3. **Update Metadata**: Add to `BENCHMARK_METADATA_V3.json`:
   ```json
   {
     "test_file_details": {
       "my_new_test_file.js": {
         "type": "vulnerability_detection",
         "cwe": "CWE-XXX",
         "functions": {},
         "description": "Description of test purpose"
       }
     }
   }
   ```

### Test Guidelines

- **Be Specific**: Each function should test ONE specific pattern
- **Be Realistic**: Patterns should reflect real-world code
- **Be Unique**: Avoid duplicate test cases
- **Annotate Clearly**: Mark VULNERABLE or SAFE explicitly
- **Cover CWEs**: Ensure coverage of all 8 CWE categories
- **Include Safe Variants**: For each vulnerability pattern, include corresponding safe pattern
- **Test Edge Cases**: Boundary conditions, unusual but valid code

### Code Style

- **Modern JavaScript**: Use ES6+ features (const/let, arrow functions, async/await)
- **Common Patterns**: Use patterns found in production Node.js applications
- **Real Dependencies**: Mock common libraries (express, axios, pg, etc.)
- **Clear Naming**: Function names should indicate what's being tested

## Design Philosophy

This benchmark suite follows principles from industry-leading benchmarks:

### Inspired By

- **CASTLE Benchmark** (CWE-based micro-benchmarks, CASTLE Score)
- **OWASP Benchmark Project** (runnable vulnerable applications)
- **Juliet Test Suite** (comprehensive CWE coverage)
- **VADER** (human-evaluated vulnerabilities)

### Key Principles

1. **Ground Truth**: Each test has clearly defined expected behavior
2. **Reproducibility**: Tests can be run and results verified
3. **Coverage**: Multiple CWEs, diverse patterns, real-world scenarios
4. **Scalability**: Modular structure allows easy addition of new tests
5. **Evaluation**: Automated framework for consistent scoring

## Usage Examples

### For Static Analysis Tool Developers

```javascript
// Run tool on benchmark suite
const results = yourTool.analyze('tests/regress/');

// Format output for evaluation
const formatted = {
    findings: results.map(r => ({
        function_name: r.function,
        cwe: r.cwe,
        file: r.file,
        line: r.line,
        confidence: r.confidence
    })),
    tool: 'YourToolName',
    timestamp: new Date().toISOString()
};

fs.writeFileSync('tool_output.json', JSON.stringify(formatted, null, 2));
```

### For Researchers

```bash
# Compare multiple tools
node evaluate_benchmark.js tests/regress/ tool1_output.json
node evaluate_benchmark.js tests/regress/ tool2_output.json
node evaluate_benchmark.js tests/regress/ tool3_output.json

# Compare results across CWEs
# Focus on specific vulnerability types
# Analyze false positive rates
# Measure precision/recall trade-offs
```

### For Benchmark Evaluation

To compare against probejs:

```bash
# Run probejs on benchmark suite
python -m probejs -t sql_injection -t xss -t os_command tests/regress/

# The results will include:
# - Detected vulnerabilities
# - Taint flows
# - Source-sink paths
# - Line numbers and code snippets
```

## Performance Characteristics

### Test Complexity

- **Simple**: Direct concatenation, basic patterns (~100 tests)
- **Medium**: Through functions, objects, arrays (~250 tests)
- **Complex**: Async flows, closures, multiple transformations (~150 tests)

### Expected Analysis Times

Based on typical static analysis tools:

- **Fast Tools**: < 1 minute for entire suite
- **Medium Tools**: 1-5 minutes for entire suite
- **Deep Analysis**: 5-15 minutes for entire suite

## Future Enhancements

Planned additions to make this a truly comprehensive suite:

### More CWEs

- **CWE-502**: Deserialization
- **CWE-200**: Information Exposure
- **CWE-352**: CSRF
- **CWE-798**: Hardcoded Credentials
- **CWE-770**: Allocation of Resources Without Limits
- **CWE-400**: Resource Exhaustion

### More Frameworks

- **NestJS**: Dependency injection patterns
- **Fastify**: Request processing patterns
- **Koa**: Middleware patterns
- **GraphQL**: Query injection
- **TypeScript**: Type system interactions

### More JavaScript Features

- **Decorators**: @decorator patterns
- **Proxies**: Proxy handler taint
- **Symbols**: Symbol-based property access
- **WeakRef/WeakMap**: Weak reference taint
- **BigInt**: Numeric type edge cases

### Real-World Applications

- **Mini-applications**: Small runnable vulnerable apps
- **CVE Reproductions**: Actual CVE vulnerability code
- **Bug Bounty Patterns**: Real vulnerabilities from bug bounty programs

## Citation

If you use this benchmark suite in your research or tool evaluation, please cite:

```
probejs Taint Analysis Benchmark Suite v2.0
World-Class Comprehensive Micro-Benchmarks for Evaluating
JavaScript Taint Bug Detection Precision and Recall
https://github.com/[username]/probejs
```

## License

This benchmark suite is part of the probejs project. See main repository for license information.

## Contact

For questions, issues, or contributions:
- **GitHub Issues**: [Repository URL]/issues
- **Documentation**: See docs/ directory for detailed documentation

## Acknowledgments

This benchmark suite design is informed by:
- CASTLE Benchmark Project
- OWASP Benchmark Project
- Juliet Test Suite for C/C++/Java
- VADER Benchmark
- Various bug bounty reports and CVE analyses
- Static analysis research papers
