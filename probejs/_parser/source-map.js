const fs = require('fs');
const path = require('path');
const { SourceMapConsumer } = require('source-map');

function normalize(filePath) {
    return path.normalize(path.resolve(filePath));
}

/** Load an inline or external source map attached to generated JavaScript. */
function loadJavaScriptSourceMap(fileName, sourceCode) {
    if (!fileName || fileName === 'stdin') return null;
    const matches = [...sourceCode.matchAll(/[/#@]\s*sourceMappingURL=([^\s]+)/g)];
    if (!matches.length) return null;
    const reference = matches[matches.length - 1][1];
    let rawMap;
    let mapDirectory = path.dirname(normalize(fileName));
    try {
        if (reference.startsWith('data:')) {
            const comma = reference.indexOf(',');
            const metadata = reference.slice(0, comma);
            const payload = reference.slice(comma + 1);
            rawMap = metadata.includes(';base64') ?
                Buffer.from(payload, 'base64').toString('utf8') : decodeURIComponent(payload);
        } else {
            const mapPath = path.resolve(path.dirname(normalize(fileName)), reference);
            rawMap = fs.readFileSync(mapPath, 'utf8');
            mapDirectory = path.dirname(mapPath);
        }
        const sourceMap = JSON.parse(rawMap);
        let originalFile = null;
        if (sourceMap.sources && sourceMap.sources.length === 1) {
            originalFile = path.resolve(mapDirectory, sourceMap.sourceRoot || '', sourceMap.sources[0]);
            if (!fs.existsSync(originalFile)) originalFile = null;
        }
        return { sourceMap, originalFile };
    } catch (_) {
        return null;
    }
}

/** Restore original locations on a generated JavaScript ESTree tree. */
function remapAstLocations(root, rawSourceMap) {
    if (!root || !rawSourceMap) return;
    const consumer = new SourceMapConsumer(rawSourceMap);
    const seen = new Set();

    function originalPosition(position) {
        if (!position) return null;
        const mapped = consumer.originalPositionFor({
            line: position.line,
            column: position.column,
            bias: SourceMapConsumer.GREATEST_LOWER_BOUND,
        });
        if (mapped.line == null || mapped.column == null) return null;
        return { line: mapped.line, column: mapped.column };
    }

    function visit(value) {
        if (!value || typeof value !== 'object' || seen.has(value)) return;
        seen.add(value);
        if (value.loc && value.loc.start && value.loc.end) {
            const generatedLoc = value.loc;
            const originalStart = originalPosition(generatedLoc.start);
            const originalEnd = originalPosition(generatedLoc.end) || originalStart;
            value.probejsGeneratedLoc = generatedLoc;
            value.probejsGenerated = !originalStart;
            if (originalStart) value.loc = { start: originalStart, end: originalEnd };
        }
        for (const key of Object.keys(value)) {
            if (!['loc', 'range', 'tokens', 'comments', 'probejsGeneratedLoc'].includes(key)) visit(value[key]);
        }
    }
    visit(root);
}

module.exports = { loadJavaScriptSourceMap, remapAstLocations };
