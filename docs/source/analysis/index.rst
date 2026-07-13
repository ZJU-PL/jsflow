Analysis Components
===================

This section covers the analysis components and frameworks in probejs that handle vulnerability detection, exploit generation, and result processing.

Overview
--------

The analysis components are responsible for:

* Performing vulnerability detection using trace rules
* Generating exploits through constraint solving
* Processing and exporting analysis results
* Managing analysis workflows and configurations

Key Components
--------------

* **Vulnerability Analyzer** (``probejs.analysis.vulnerability``): Core vulnerability detection engine
* **Exploit Generator** (``probejs.analysis.exploit``): Automatic exploit generation
* **Result Processor** (``probejs.analysis.results``): Analysis result processing and export
* **Workflow Manager** (``probejs.analysis.workflow``): Analysis workflow orchestration

.. toctree::
   :maxdepth: 2

   vulnerability