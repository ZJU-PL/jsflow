#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

class BenchmarkEvaluator {
    constructor() {
        this.results = {
            true_positives: 0,
            false_positives: 0,
            true_negatives: 0,
            false_negatives: 0,
            by_cwe: {},
            by_category: {}
        };
    }

    async evaluate(benchmarkDir, toolOutput) {
        console.log('Starting benchmark evaluation...');
        console.log(`Benchmark directory: ${benchmarkDir}`);
        console.log(`Tool output: ${toolOutput}`);

        const metadata = this.loadMetadata(benchmarkDir);
        const testFiles = this.listTestFiles(benchmarkDir);

        console.log(`\nFound ${testFiles.length} test files`);

        for (const testFile of testFiles) {
            await this.evaluateTestFile(benchmarkDir, testFile, toolOutput, metadata);
        }

        this.calculateMetrics();
        this.printReport();
    }

    loadMetadata(benchmarkDir) {
        const metadataV3 = path.join(benchmarkDir, 'BENCHMARK_METADATA_V3.json');
        const metadataV2 = path.join(benchmarkDir, 'BENCHMARK_METADATA_V2.json');
        const metadataPath = fs.existsSync(metadataV3) ? metadataV3 : metadataV2;
        if (metadataPath && fs.existsSync(metadataPath)) {
            const content = fs.readFileSync(metadataPath, 'utf8');
            return JSON.parse(content);
        }

        console.warn('Metadata file not found, using minimal metadata');
        return { test_file_details: {} };
    }

    listTestFiles(benchmarkDir) {
        const files = [];
        const skipDirs = new Set(['recall', 'flows']);

        const walk = (dir, relativeBase = '') => {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                if (entry.isDirectory()) {
                    if (skipDirs.has(entry.name)) continue;
                    const nextRelative = relativeBase
                        ? path.join(relativeBase, entry.name)
                        : entry.name;
                    walk(path.join(dir, entry.name), nextRelative);
                    continue;
                }

                if (!entry.isFile() || !entry.name.endsWith('.js')) continue;
                if (entry.name === 'evaluate_benchmark.js') continue;
                files.push(relativeBase ? path.join(relativeBase, entry.name) : entry.name);
            }
        };

        walk(benchmarkDir);
        return files;
    }

    async evaluateTestFile(benchmarkDir, testFile, toolOutput, metadata) {
        const filePath = path.join(benchmarkDir, testFile);
        const content = fs.readFileSync(filePath, 'utf8');

        const fileMetadata = metadata.test_file_details[path.basename(testFile)] || {};
        const expectedCWE = fileMetadata.cwe;
        const expectedType = fileMetadata.type;

        const functions = this.extractFunctions(content);

        console.log(`\nEvaluating ${testFile}: ${functions.length} functions`);

        for (const func of functions) {
            this.evaluateFunction(func, expectedCWE, expectedType, toolOutput);
        }
    }

    extractFunctions(content) {
        const functionRegex = /function\s+(\w+)\s*\([^)]*\)/g;
        const matches = content.matchAll(functionRegex);
        return matches.map(match => ({
            name: match[1],
            line: this.getLineNumber(content, match.index)
        }));
    }

    getLineNumber(content, index) {
        return content.substring(0, index).split('\n').length;
    }

    evaluateFunction(func, expectedCWE, expectedType, toolOutput) {
        const expectedBehavior = this.determineExpectedBehavior(func, expectedType);
        const actualDetection = this.checkToolDetection(func, toolOutput, expectedCWE);

        this.recordResult(func, expectedBehavior, actualDetection, expectedCWE);
    }

    determineExpectedBehavior(func, expectedType) {
        if (expectedType === 'precision') {
            return 'safe';
        }
        return 'vulnerable';
    }

    checkToolDetection(func, toolOutput, expectedCWE) {
        if (!toolOutput || !toolOutput.findings) {
            return false;
        }

        return toolOutput.findings.some(finding =>
            finding.function_name === func.name &&
            finding.cwe === expectedCWE
        );
    }

    recordResult(func, expected, actual, cwe) {
        const isVulnerableExpected = expected === 'vulnerable';
        const isVulnerableDetected = actual;

        if (isVulnerableExpected && isVulnerableDetected) {
            this.results.true_positives++;
        } else if (!isVulnerableExpected && !isVulnerableDetected) {
            this.results.true_negatives++;
        } else if (!isVulnerableExpected && isVulnerableDetected) {
            this.results.false_positives++;
        } else if (isVulnerableExpected && !isVulnerableDetected) {
            this.results.false_negatives++;
        }

        this.recordByCWE(cwe, expected, actual);
    }

    recordByCWE(cwe, expected, actual) {
        if (!this.results.by_cwe[cwe]) {
            this.results.by_cwe[cwe] = {
                tp: 0, fp: 0, tn: 0, fn: 0
            };
        }

        const isVulnerableExpected = expected === 'vulnerable';
        const isVulnerableDetected = actual;

        if (isVulnerableExpected && isVulnerableDetected) {
            this.results.by_cwe[cwe].tp++;
        } else if (!isVulnerableExpected && !isVulnerableDetected) {
            this.results.by_cwe[cwe].tn++;
        } else if (!isVulnerableExpected && isVulnerableDetected) {
            this.results.by_cwe[cwe].fp++;
        } else if (isVulnerableExpected && !isVulnerableDetected) {
            this.results.by_cwe[cwe].fn++;
        }
    }

    calculateMetrics() {
        const total = this.results.true_positives +
                      this.results.false_positives +
                      this.results.true_negatives +
                      this.results.false_negatives;

        if (total === 0) return;

        const vulnerableTests = this.results.true_positives + this.results.false_negatives;
        const safeTests = this.results.false_positives + this.results.true_negatives;

        this.results.precision = safeTests > 0
            ? this.results.true_positives / (this.results.true_positives + this.results.false_positives)
            : 1.0;

        this.results.recall = vulnerableTests > 0
            ? this.results.true_positives / (this.results.true_positives + this.results.false_negatives)
            : 1.0;

        this.results.f1_score = this.results.precision > 0 && this.results.recall > 0
            ? 2 * (this.results.precision * this.results.recall) /
              (this.results.precision + this.results.recall)
            : 0.0;
    }

    printReport() {
        console.log('\n' + '='.repeat(60));
        console.log('BENCHMARK EVALUATION REPORT');
        console.log('='.repeat(60));

        console.log('\nOVERALL RESULTS:');
        console.log('  True Positives:  ', this.results.true_positives);
        console.log('  False Positives: ', this.results.false_positives);
        console.log('  True Negatives:  ', this.results.true_negatives);
        console.log('  False Negatives: ', this.results.false_negatives);

        console.log('\nMETRICS:');
        console.log(`  Precision: ${(this.results.precision * 100).toFixed(2)}%`);
        console.log(`  Recall:    ${(this.results.recall * 100).toFixed(2)}%`);
        console.log(`  F1 Score:  ${this.results.f1_score.toFixed(4)}`);

        console.log('\nBY CWE:');
        for (const [cwe, data] of Object.entries(this.results.by_cwe)) {
            const precision = data.tp + data.fp > 0
                ? data.tp / (data.tp + data.fp)
                : 1.0;
            const recall = data.tp + data.fn > 0
                ? data.tp / (data.tp + data.fn)
                : 1.0;

            console.log(`  ${cwe}:`);
            console.log(`    TP: ${data.tp}, FP: ${data.fp}, TN: ${data.tn}, FN: ${data.fn}`);
            console.log(`    Precision: ${(precision * 100).toFixed(2)}%`);
            console.log(`    Recall:    ${(recall * 100).toFixed(2)}%`);
        }

        console.log('\n' + '='.repeat(60));
    }
}

if (require.main === module) {
    const args = process.argv.slice(2);

    if (args.length < 2) {
        console.log('Usage: node evaluate_benchmark.js <benchmark_dir> <tool_output.json>');
        process.exit(1);
    }

    const [benchmarkDir, toolOutputPath] = args;

    const evaluator = new BenchmarkEvaluator();

    if (!fs.existsSync(toolOutputPath)) {
        console.error(`Tool output file not found: ${toolOutputPath}`);
        console.error('Using simulated results for demonstration');

        const simulatedOutput = {
            findings: [],
            tool: 'probejs',
            timestamp: new Date().toISOString()
        };

        evaluator.evaluate(benchmarkDir, simulatedOutput);
    } else {
        const toolOutput = JSON.parse(fs.readFileSync(toolOutputPath, 'utf8'));
        evaluator.evaluate(benchmarkDir, toolOutput);
    }
}

module.exports = BenchmarkEvaluator;
