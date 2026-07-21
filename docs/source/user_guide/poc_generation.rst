PoC Generation Workflows (Experimental)
========================================

.. warning::

   The PoC generation utilities described in this document are **experimental** and **separate from probejs's core static analysis pipeline**. They consume ``report.json`` output as input but rely on external LLM-based coding agents (e.g., Codex, Claude) rather than automated symbolic reasoning. Results are not guaranteed and should be manually validated.

probejs ships with two experimental PoC generation solutions. They share the same ``report.json`` contract, but they are separate implementations with different operational goals.

Shared Report Contract
----------------------

Run probejs with structured reporting and, when useful, auto-exploit solving:

.. code-block:: bash

   python -m probejs --json -m -X -t os_command package/index.js

The output report contains:

- ``finding.poc.agent_packet``: compact, agent-facing task packet.
- ``finding.poc.thin_slice``: evidence-oriented hybrid thin slice.
- ``finding.poc.entrypoint_contract``: recovered import/call information.
- ``finding.poc.payload_contract``: where the payload belongs and what the sink should observe.
- ``finding.poc.validation_oracle``: preferred and fallback success checks.
- ``finding.poc.runtime_environment``: install/build/mock hints.
- ``finding.poc.agent_todo``: suggested implementation checklist.

Use ``agent_packet`` as the default input to coding agents. Treat the rest of ``finding.poc`` and the full ``report.json`` as an evidence store that should be loaded only when the compact packet is insufficient or validation fails.

Solution A: Interactive Skill Workflow
--------------------------------------

Location: ``tools/pocgen/skills/probejs-poc-generation/``

This solution is a Codex skill. It is intended for interactive use when a human or agent is already working inside this repository and wants guidance for turning one probejs finding into a runnable PoC.

Use it when:

- You want a human-in-the-loop workflow.
- You are manually inspecting one finding.
- You want the agent to adapt templates and explain assumptions.
- You do not need reproducible batch execution across many packages.

Inputs:

- Prefer ``finding.poc.agent_packet``.
- If needed, read selected evidence from ``finding.poc.thin_slice``, ``finding.poc.trace``, ``finding.path``, and ``finding.rule_evaluation``.
- Avoid loading the full report by default.

Outputs:

- ``poc.js``, ``poc.mjs``, ``http-request.txt``, or another minimal artifact.
- ``README-PoC.md``.
- Honest validation status and remaining uncertainty.

This is a prompt/template solution. It does not own a durable orchestration loop, retry policy, multi-agent backend selection, or benchmark-grade run logs.

Solution B: Automated Runner Workflow
-------------------------------------

Location: ``tools/pocgen/``

This solution is a normal Python implementation, similar in shape to BugAtlas: prompts plus a CLI runner that can call a headless coding agent such as Codex, OpenCode, or Claude Code.

Use it when:

- You need reproducible PoC generation.
- You want batch evaluation across packages/findings.
- You need consistent context budgeting and evidence-on-demand behavior.
- You want automated validation and repair attempts.
- You need run logs, transcripts, and comparable success/failure metrics.

Structure::

   tools/pocgen/
     README.md
     generate.py
     agent_runner.py
     packet.py
     evidence.py
     validate.py
     prompts/
       generate.md
       repair.md
       validate.md
     templates/
       direct-call.cjs
       esm-import.mjs
       proto-poc.cjs
       README-PoC.md

Command shape:

.. code-block:: bash

   python tools/pocgen/generate.py \
     --report logs/<timestamp>/report.json \
     --finding 0 \
     --agent codex \
     --model default \
     --output evaluation/pocs/<case-id>/

Recommended execution policy:

1. Extract ``finding.poc.agent_packet``.
2. Run the coding CLI in the target package root with only the compact packet.
3. Validate the generated PoC.
4. If validation fails, retry with ``finding.poc.thin_slice``.
5. If it still fails, retry with selected trace/rule evidence.
6. Only load the full finding as a last resort.
7. Save artifacts, validation output, prompts, and agent transcript.

This is an executable pipeline solution. It should not be hidden inside the skill because it needs durable state, batch controls, backend selection, validation, retries, and result accounting.

Why Keep Both?
--------------

The skill and the runner solve different problems:

+----------------------+----------------------+----------------------+
| Property             | Interactive Skill    | Automated Runner    |
+======================+======================+======================+
| Primary user         | Human-assisted       | Batch/reproducible  |
|                      | Codex session        | pipeline             |
+----------------------+----------------------+----------------------+
| Implementation       | Skill instructions   | Python CLI plus     |
|                      | and templates        | prompts              |
+----------------------+----------------------+----------------------+
| Default input        | ``finding.poc.       | ``finding.poc.       |
|                      | agent_packet``       | agent_packet``       |
+----------------------+----------------------+----------------------+
| Evidence loading     | Agent reads on       | Script controls     |
|                      | demand               | staged evidence      |
+----------------------+----------------------+----------------------+
| Validation           | Manual or            | Automated, logged,   |
|                      | agent-driven         | retryable            |
+----------------------+----------------------+----------------------+
| Best for             | One-off PoC work     | Benchmarking and     |
|                      |                      | large-scale PoC      |
|                      |                      | generation           |
+----------------------+----------------------+----------------------+

The skill should document how to reason about a finding. The automated runner should implement the repeatable process.
