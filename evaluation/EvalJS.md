## Evaluation for JavaScript Vulnerability Detection

## Baslines for JavaScript Vulnerability Detection

- **FAST**
  + (probejs is built on top of FAST)
  + S&P 23: Scaling JavaScript Abstract Interpretation to Detect and Exploit Node.js Taint-style Vulnerability. Mingqing Kang, Yichao Xu, Song Li, Rigel Gjomemo, Jianwei Hou, V.N. Venkatakrishnan, and Yinzhi Cao. 
  + https://github.com/fast-sp-2023/fast
- **ODGen**
  + USENIX Security 22: Mining Node.js Vulnerabilities via Object Dependence Graph and Query. Song Li, Mingqing Kang, Jianwei Hou, and Yinzhi Cao.
  + https://github.com/Song-Li/ODGen
- **Graph.js**
  + PLDI 24: Efficient Static Vulnerability Analysis for JavaScript with Multiversion Dependency Graphs. Mafalda Ferreira, Miguel Monteiro, Tiago Brito, Miguel E. Coimbra, Nuno Santos, Limin Jia, and José Fragoso Santos.
  + https://github.com/formalsec/graphjs
  

## Exploit Generation for JavaScript

- **explore-js**
  + PLDI 25: Automated Exploit Generation for Node.js Packages. Filipe Marques, Mafalda Ferreira, André Nascimento, Miguel E. Coimbra, Nuno Santos, Limin Jia, José Fragoso Santos.
  + https://github.com/formalsec/explode-js, https://github.com/formalsec/explodejs-datasets
- **NODEMEDIC-FINE**
  + NDSS 25: NODEMEDIC-FINE: Automatic
Detection and Exploit Synthesis for Node.js Vulnerabilities. Darion Cassel, Nuno Sabino, Min-Chien Hsu, Ruben Martins, and Limin Jia. 
  + https://github.com/NodeMedicAnalysis/NodeMedic-FINE


## Dataset for JavaScript Vulnerability Detection

All datasets below are included in `evaluation/explodejs-datasets/`, cloned from https://github.com/formalsec/explodejs-datasets. The `run_bench.py` script uses the pre-extracted source files (`src/index.js`) in each dataset.

- **VulcaN**
  + TR 23: Study of JavaScript Static Analysis Tools for Vulnerability Detection in Node.js Packages.  Tiago Brito, Mafalda Ferreira, Miguel Monteiro, Pedro Lopes, Miguel Barros, José Fragoso Santos, and Nuno Santos.
  + Full dataset: https://github.com/formalsec/vulcan-dataset
    + Contains **95 CWE categories** with 957 advisory reviews across ~1,400+ packages (as `.tgz` archives)
    + Each advisory includes: CWE/CVE identifiers, vulnerability location, proof of concept, patch, and tool outputs scored A-D
  + A **subset** of the VulcaN dataset (4 CWEs with pre-extracted source) is included in `explodejs-datasets/vulcan-dataset/`:
    + `CWE-22` (path_traversal): 5 cases
    + `CWE-78` (os_command): 66 cases
    + `CWE-94` (code_exec): 22 cases
    + `CWE-471` (proto_pollution): 67 cases
    + See also the full repo for other CWEs (e.g., CWE-79 XSS, CWE-89 SQLi, CWE-400 DoS, CWE-1321 PP, CWE-20, CWE-77, CWE-601, CWE-918 SSRF, etc.)
- **SecBench.js**
  + ICSE 23: SecBench.js: An Executable Security Benchmark Suite for Server-Side JavaScript. Masudul Hasan Masud Bhuiyan, Adithya Srinivas Parthasarathy, Nikos Vasilakis, Michael Pradel, and CristianAlexandru Staicu
  + Pre-extracted in `explodejs-datasets/secbench-dataset/`:
    + `CWE-22` (path_traversal): 161 cases
    + `CWE-78` (os_command): 83 cases
    + `CWE-94` (code_exec): 20 cases
    + `CWE-471` (proto_pollution): 120 cases
- **explore.js collected dataset** (PLDI 25)
  + "Collected consists of 32,137 popular real-world Node.js packages crawled from the npm repository in September 2023. We consider a package to be popular if it had ≥ 2,000 weekly downloads at the time of collection. For the collected dataset, there is no ground truth because we did not manually analyze the source code of the packages to identify exploits"
  + Pre-extracted in `explodejs-datasets/collected-dataset/`

## probejs Evaluation Results

Run the benchmark with `python3 evaluation/run_bench.py [-d DATASET_DIR] [-j JOBS]`.

### SecBench.js (`explodejs-datasets/secbench-dataset/`)

| Metric | Value |
|---|---|
| Total cases | 384 |
| True Positives | 355 |
| False Negatives | 9 |
| Timeouts | 20 |
| Errors | 0 |
| Recall | **97.53%** (355/364) |
| Avg time | 0.5s |

| CWE | Type | Detected/Total | Recall |
|---|---|---|---|
| CWE-22 | Path Traversal | 159/161 | 98.8% |
| CWE-78 | OS Command | 83/83 | 100% |
| CWE-94 | Code Execution | 20/20 | 100% |
| CWE-471 | Prototype Pollution | 93/120 | 77.5% |

### VulcaN (subset, `explodejs-datasets/vulcan-dataset/`)

| Metric | Value |
|---|---|
| Total cases | 160 |
| True Positives | 138 |
| False Negatives | 2 |
| Timeouts | 20 |
| Errors | 0 |
| Recall | **98.57%** (138/140) |
| Avg time | 1.1s |

| CWE | Type | Detected/Total | Recall |
|---|---|---|---|
| CWE-22 | Path Traversal | 5/5 | 100% |
| CWE-78 | OS Command | 66/66 | 100% |
| CWE-94 | Code Execution | 21/22 | 95.5% |
| CWE-471 | Prototype Pollution | 46/67 | 68.7% |