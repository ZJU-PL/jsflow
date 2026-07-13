#!/usr/bin/env python3
"""
Evaluate probejs on tests/regress directory to calculate precision and recall.

This script:
1. Runs probejs on each test file with appropriate vulnerability type
2. Determines expected behavior (vulnerable vs safe) from file names and metadata
3. Parses probejs output to detect if vulnerabilities were found
4. Calculates precision, recall, and F1 score
"""

import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Map CWE IDs to probejs vulnerability types
CWE_TO_VULN_TYPE = {
    "CWE-89": "code_exec",  # SQL Injection (probejs may not have specific SQL injection type)
    "CWE-78": "os_command",  # OS Command Injection
    "CWE-79": "xss",  # Cross-Site Scripting
    "CWE-94": "code_exec",  # Code Execution
    "CWE-22": "path_traversal",  # Path Traversal
    "CWE-943": "nosql",  # NoSQL Injection
    "CWE-918": "code_exec",  # SSRF (treated as code execution)
    "CWE-1321": "proto_pollution",  # Prototype Pollution
    "CWE-502": "code_exec",  # Deserialization (treated as code execution)
    "CWE-200": "code_exec",  # Information Exposure (treated as code execution)
    "CWE-352": "code_exec",  # CSRF (treated as code execution)
}

# Map file patterns to CWE
FILE_TO_CWE = {
    "sql_injection": "CWE-89",
    "os_command": "CWE-78",
    "xss": "CWE-79",
    "code_execution": "CWE-94",
    "path_traversal": "CWE-22",
    "nosql": "CWE-943",
    "ssrf": "CWE-918",
    "prototype_pollution": "CWE-1321",
    "deserialization": "CWE-502",
    "information_exposure": "CWE-200",
    "csrf": "CWE-352",
    "ssti": "CWE-94",
    "graphql": "CWE-89",  # GraphQL injection similar to SQL
    "jwt": "CWE-94",
}

DEFAULT_TIMEOUT = 60  # seconds per file


def load_metadata(metadata_path: Path) -> Dict:
    """Load benchmark metadata."""
    if metadata_path.exists():
        with open(metadata_path, 'r') as f:
            return json.load(f)
    return {}


def determine_cwe_from_filename(filename: str) -> Optional[str]:
    """Determine CWE from filename."""
    filename_lower = filename.lower()
    for pattern, cwe in FILE_TO_CWE.items():
        if pattern in filename_lower:
            return cwe
    return None


def is_safe_file(filename: str) -> bool:
    """Determine if a file is a precision test (should be safe)."""
    return "_safe.js" in filename.lower() or "precision_" in filename.lower()


def get_vuln_type_for_file(filename: str, metadata: Dict) -> Optional[str]:
    """Get the vulnerability type to use for probejs."""
    # Check metadata first
    file_details = metadata.get("test_file_details", {}).get(filename, {})
    cwe = file_details.get("cwe")
    
    if not cwe:
        cwe = determine_cwe_from_filename(filename)
    
    if cwe:
        return CWE_TO_VULN_TYPE.get(cwe)
    
    return None


def run_probejs(file_path: Path, vuln_type: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, float, str]:
    """Run probejs on a file and return (detected, elapsed_time, output)."""
    script_path = Path(__file__).resolve()
    if script_path.parent.name == "evaluation":
        project_root = script_path.parent.parent
    else:
        project_root = script_path.parent
    
    cmd = ["python3", "-m", "probejs", "-t", vuln_type, "-q", "-m", str(file_path)]
    start_time = time.time()
    
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Combine stderr into stdout
            text=True,
            cwd=project_root,
            bufsize=1
        )
        stdout, _ = proc.communicate(timeout=timeout)
        elapsed_time = time.time() - start_time
        
        output = stdout or ""
        # Remove ANSI color codes
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', output)
        
        # Check if vulnerability was detected
        # Look for "Detection: successful" in the output
        detected = (
            "Detection: successful" in clean_output or
            ("success:" in clean_output.lower() and "vul_checking" in clean_output.lower() and "success:  [" in clean_output and "success:  []" not in clean_output)
        )
        
        return detected, elapsed_time, clean_output
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return False, time.time() - start_time, "Timeout"
    except Exception as e:
        return False, time.time() - start_time, f"Error: {str(e)}"


def extract_functions_from_file(file_path: Path) -> List[Dict]:
    """Extract function names and their annotations from a JavaScript file."""
    functions = []
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Find all function definitions
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)'
        for match in re.finditer(func_pattern, content):
            func_name = match.group(1)
            start_pos = match.start()
            
            # Look for VULNERABLE or SAFE annotation before the function
            # Check up to 10 lines before
            lines_before = content[:start_pos].split('\n')
            annotation = None
            for line in reversed(lines_before[-10:]):
                if '// VULNERABLE' in line or 'VULNERABLE:' in line:
                    annotation = 'vulnerable'
                    break
                elif '// SAFE' in line or 'SAFE:' in line:
                    annotation = 'safe'
                    break
            
            functions.append({
                'name': func_name,
                'annotation': annotation
            })
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    
    return functions


def evaluate_file(file_path: Path, metadata: Dict, results: Dict) -> Dict:
    """Evaluate a single test file."""
    filename = file_path.name
    is_safe = is_safe_file(filename)
    
    # Get vulnerability type
    vuln_type = get_vuln_type_for_file(filename, metadata)
    if not vuln_type:
        print(f"  Skipping {filename}: unknown vulnerability type")
        return None
    
    # Get file metadata
    file_meta = metadata.get("test_file_details", {}).get(filename, {})
    file_type = file_meta.get("type", "vulnerability_detection")
    
    # Determine expected behavior
    # Files with "_safe" or "precision_" should not have vulnerabilities detected
    # Files with "vulnerable" or type "vulnerability_detection" should have vulnerabilities detected
    if is_safe or file_type == "precision":
        expected_vulnerable = False
    elif "vulnerable" in filename.lower() or file_type == "vulnerability_detection":
        expected_vulnerable = True
    else:
        # Default: assume vulnerable if not explicitly marked as safe
        expected_vulnerable = True
    
    print(f"Analyzing {filename} (type: {vuln_type}, expected: {'vulnerable' if expected_vulnerable else 'safe'})")
    
    # Run probejs
    detected, elapsed_time, output = run_probejs(file_path, vuln_type)
    
    # Classify result
    if expected_vulnerable and detected:
        result_type = "TP"  # True Positive
        results['tp'] += 1
    elif expected_vulnerable and not detected:
        result_type = "FN"  # False Negative
        results['fn'] += 1
    elif not expected_vulnerable and detected:
        result_type = "FP"  # False Positive
        results['fp'] += 1
    else:
        result_type = "TN"  # True Negative
        results['tn'] += 1
    
    # Update CWE-specific stats
    cwe = file_meta.get("cwe") or determine_cwe_from_filename(filename)
    if cwe:
        if cwe not in results['by_cwe']:
            results['by_cwe'][cwe] = {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0}
        results['by_cwe'][cwe][result_type.lower()] += 1
    
    print(f"  Result: {result_type} ({elapsed_time:.1f}s)")
    
    return {
        'file': filename,
        'vuln_type': vuln_type,
        'expected': 'vulnerable' if expected_vulnerable else 'safe',
        'detected': detected,
        'result': result_type,
        'time': elapsed_time,
        'cwe': cwe
    }


def calculate_metrics(results: Dict):
    """Calculate precision, recall, and F1 score."""
    tp = results['tp']
    fp = results['fp']
    tn = results['tn']
    fn = results['fn']
    
    # Precision = TP / (TP + FP)
    if tp + fp > 0:
        results['precision'] = tp / (tp + fp)
    else:
        results['precision'] = 1.0 if tp > 0 else 0.0
    
    # Recall = TP / (TP + FN)
    if tp + fn > 0:
        results['recall'] = tp / (tp + fn)
    else:
        results['recall'] = 1.0 if tp > 0 else 0.0
    
    # F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
    if results['precision'] + results['recall'] > 0:
        results['f1'] = 2 * (results['precision'] * results['recall']) / (results['precision'] + results['recall'])
    else:
        results['f1'] = 0.0
    
    # Calculate metrics per CWE
    for cwe, stats in results['by_cwe'].items():
        cwe_tp = stats['tp']
        cwe_fp = stats['fp']
        cwe_fn = stats['fn']
        
        if cwe_tp + cwe_fp > 0:
            stats['precision'] = cwe_tp / (cwe_tp + cwe_fp)
        else:
            stats['precision'] = 1.0 if cwe_tp > 0 else 0.0
        
        if cwe_tp + cwe_fn > 0:
            stats['recall'] = cwe_tp / (cwe_tp + cwe_fn)
        else:
            stats['recall'] = 1.0 if cwe_tp > 0 else 0.0
        
        if stats['precision'] + stats['recall'] > 0:
            stats['f1'] = 2 * (stats['precision'] * stats['recall']) / (stats['precision'] + stats['recall'])
        else:
            stats['f1'] = 0.0


def print_results(results: Dict):
    """Print evaluation results."""
    print("\n" + "=" * 70)
    print("PROBEJS PRECISION AND RECALL EVALUATION")
    print("=" * 70)
    
    tp = results['tp']
    fp = results['fp']
    tn = results['tn']
    fn = results['fn']
    total = tp + fp + tn + fn
    
    print(f"\nOverall Results ({total} test files):")
    print(f"  True Positives (TP):  {tp:4d} - Vulnerabilities correctly detected")
    print(f"  False Positives (FP): {fp:4d} - Safe code incorrectly flagged")
    print(f"  True Negatives (TN):  {tn:4d} - Safe code correctly not flagged")
    print(f"  False Negatives (FN): {fn:4d} - Vulnerabilities not detected")
    
    print(f"\nMetrics:")
    print(f"  Precision: {results['precision']*100:6.2f}%  (TP / (TP + FP))")
    print(f"  Recall:    {results['recall']*100:6.2f}%  (TP / (TP + FN))")
    print(f"  F1 Score:  {results['f1']:6.4f}")
    
    if results['by_cwe']:
        print(f"\nPer-CWE Breakdown:")
        for cwe in sorted(results['by_cwe'].keys()):
            stats = results['by_cwe'][cwe]
            cwe_total = stats['tp'] + stats['fp'] + stats['tn'] + stats['fn']
            if cwe_total > 0:
                print(f"  {cwe}:")
                print(f"    TP: {stats['tp']}, FP: {stats['fp']}, TN: {stats['tn']}, FN: {stats['fn']}")
                print(f"    Precision: {stats['precision']*100:6.2f}%, Recall: {stats['recall']*100:6.2f}%, F1: {stats['f1']:6.4f}")
    
    print("\n" + "=" * 70)


def main():
    """Main evaluation function."""
    # Get paths
    script_path = Path(__file__).resolve()
    # If script is in evaluation/, go up one level; if in root, use current dir
    if script_path.parent.name == "evaluation":
        project_root = script_path.parent.parent
    else:
        project_root = script_path.parent
    regress_dir = project_root / "tests" / "regress"
    metadata_path = regress_dir / "BENCHMARK_METADATA_V3.json"
    
    if not regress_dir.exists():
        print(f"Error: {regress_dir} does not exist")
        sys.exit(1)
    
    # Load metadata
    metadata = load_metadata(metadata_path)
    
    # Initialize results
    results = {
        'tp': 0,
        'fp': 0,
        'tn': 0,
        'fn': 0,
        'by_cwe': {},
        'cases': []
    }
    
    # Find all JavaScript test files (recursively) and keep evaluation-focused ones
    test_files = sorted(
        [
            f for f in regress_dir.rglob("*.js")
            if f.name not in ["evaluate_benchmark.js"]
        ]
    )
    test_files = [
        f for f in test_files
        if "recall" not in f.parts and "flows" not in f.parts
    ]
    
    print(f"Found {len(test_files)} test files to evaluate\n")
    
    # Evaluate each file
    for test_file in test_files:
        case_result = evaluate_file(test_file, metadata, results)
        if case_result:
            results['cases'].append(case_result)
    
    # Calculate metrics
    calculate_metrics(results)
    
    # Print results
    print_results(results)
    
    # Save results to JSON
    output_file = project_root / "evaluation_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    main()
