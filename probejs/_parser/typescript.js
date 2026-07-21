const fs = require('fs');
const path = require('path');
const vm = require('vm');
const bundledTypeScriptPath = require.resolve('typescript');
const bundledTypeScript = require(bundledTypeScriptPath);
let ts = bundledTypeScript;
let activeTypeScriptPath = bundledTypeScriptPath;
const { SourceMapConsumer } = require('source-map');

const TYPESCRIPT_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts', '.ets']);
const DECLARATION_FILE_RE = /\.d\.[cm]?ts$/i;

function normalize(filePath) {
    return path.normalize(path.resolve(filePath));
}

function activateProjectTypeScript(fileName) {
    let resolvedPath = bundledTypeScriptPath;
    if (fileName && fileName !== 'stdin') {
        try {
            resolvedPath = require.resolve('typescript', { paths: [path.dirname(normalize(fileName))] });
        } catch (_) {
            resolvedPath = bundledTypeScriptPath;
        }
    }
    if (resolvedPath !== activeTypeScriptPath) {
        ts = require(resolvedPath);
        activeTypeScriptPath = resolvedPath;
    }
    return { path: activeTypeScriptPath, version: ts.version || 'unknown' };
}

function isTypeScriptFile(filePath) {
    return Boolean(filePath) && TYPESCRIPT_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function isRuntimeSourceFile(filePath) {
    return isTypeScriptFile(filePath) && !DECLARATION_FILE_RE.test(filePath);
}

function isArkTSFile(filePath) {
    return Boolean(filePath) && path.extname(filePath).toLowerCase() === '.ets';
}

function readJson5(fileName) {
    try {
        const source = fs.readFileSync(fileName, 'utf8');
        return vm.runInNewContext(`(${source})`, Object.create(null), {
            timeout: 50,
            contextCodeGeneration: { strings: false, wasm: false },
        });
    } catch (_) {
        return null;
    }
}

function discoverArkTSProject(fileName) {
    if (!fileName || fileName === 'stdin') return null;
    let current = path.dirname(normalize(fileName));
    let root = null;
    while (current !== path.dirname(current)) {
        if (fs.existsSync(path.join(current, 'build-profile.json5'))) {
            root = current;
            break;
        }
        current = path.dirname(current);
    }
    if (!root) return null;

    const buildProfilePath = path.join(root, 'build-profile.json5');
    const buildProfile = readJson5(buildProfilePath) || {};
    const modules = [];
    for (const moduleRecord of buildProfile.modules || []) {
        const moduleRoot = path.resolve(root, moduleRecord.srcPath || moduleRecord.name || '.');
        const moduleConfigPath = path.join(moduleRoot, 'src', 'main', 'module.json5');
        const moduleConfig = readJson5(moduleConfigPath) || {};
        const descriptor = moduleConfig.module || moduleConfig;
        const entrypoints = [];
        for (const key of ['srcEntry', 'mainElement']) {
            if (descriptor[key]) entrypoints.push(descriptor[key]);
        }
        for (const ability of [...(descriptor.abilities || []), ...(descriptor.extensionAbilities || [])]) {
            if (ability.srcEntry) entrypoints.push(ability.srcEntry);
            if (ability.name) entrypoints.push(ability.name);
        }
        modules.push({
            name: moduleRecord.name || descriptor.name || path.basename(moduleRoot),
            root: moduleRoot,
            config: fs.existsSync(moduleConfigPath) ? moduleConfigPath : null,
            entrypoints: [...new Set(entrypoints)],
        });
    }

    const ohPackagePath = path.join(root, 'oh-package.json5');
    const ohPackage = readJson5(ohPackagePath) || {};
    const dependencies = Object.assign({}, ohPackage.dependencies || {}, ohPackage.devDependencies || {});
    return {
        root,
        buildProfile: buildProfilePath,
        modules,
        dependencies,
    };
}

function normalizeArkTSSource(sourceCode) {
    const entryComponents = [];
    const entryPattern = /@Entry(?:\s*\([^)]*\))?[\s\S]*?\bstruct\s+([A-Za-z_$][\w$]*)/g;
    let entryMatch;
    while ((entryMatch = entryPattern.exec(sourceCode)) !== null) entryComponents.push(entryMatch[1]);
    const normalizedDecorators = sourceCode.replace(
        /@(?:Entry|Component|State|Prop|Link|Provide|Consume|ObjectLink|Observed|Builder|BuilderParam|Styles|Extend|Watch|Local|Param|Event|Once)\b(?:\([^)]*\))?\s*/g,
        '',
    );
    const lines = normalizedDecorators.replace(/\bstruct(\s+[A-Za-z_$][\w$]*)/g, 'class$1').split('\n');
    const componentDepths = [];
    let depth = 0;
    const normalizedSource = lines.map((originalLine) => {
        let line = originalLine;
        const opens = (originalLine.match(/\{/g) || []).length;
        const closes = (originalLine.match(/\}/g) || []).length;
        const trimmed = line.trim();
        if (componentDepths.length && componentDepths[componentDepths.length - 1] === depth && /^}/.test(trimmed)) {
            line = line.slice(0, line.search(/\S/));
            componentDepths.pop();
        }
        const componentOpen = /^\s*[A-Z][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\([^;]*\)\s*\{\s*$/.test(line);
        if (componentOpen) {
            line = line.slice(0, line.search(/\S/));
            componentDepths.push(depth + 1);
        }
        depth += opens - closes;
        return line;
    }).join('\n');

    function extractBuildBody(className) {
        const classStart = normalizedSource.search(new RegExp(`\\bclass\\s+${className}\\b`));
        if (classStart < 0) return null;
        const methodMatch = /\bbuild\s*\([^)]*\)\s*\{/.exec(normalizedSource.slice(classStart));
        if (!methodMatch) return null;
        const openBrace = classStart + methodMatch.index + methodMatch[0].lastIndexOf('{');
        let nested = 1;
        for (let index = openBrace + 1; index < normalizedSource.length; index++) {
            if (normalizedSource[index] === '{') nested++;
            if (normalizedSource[index] === '}') nested--;
            if (nested === 0) return normalizedSource.slice(openBrace + 1, index);
        }
        return null;
    }

    const entryBodies = entryComponents
        .map(extractBuildBody)
        .filter(Boolean)
        .map((body) => `\n${body}\n`)
        .join('');
    return normalizedSource + entryBodies + '\nexport {};\n';
}

function formatDiagnostic(diagnostic) {
    const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n');
    const formatted = {
        source: 'typescript',
        code: `TS${diagnostic.code}`,
        category: String(ts.DiagnosticCategory[diagnostic.category] || 'error').toLowerCase(),
        message,
        file: null,
        line: null,
        column: null,
    };
    if (!diagnostic.file || diagnostic.start === undefined) {
        return formatted;
    }
    const position = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
    formatted.file = diagnostic.file.fileName;
    formatted.line = position.line + 1;
    formatted.column = position.character + 1;
    return formatted;
}

function diagnosticText(diagnostic) {
    const location = diagnostic.file ? `${diagnostic.file}:${diagnostic.line}:${diagnostic.column} ` : '';
    return `${location}${diagnostic.code}: ${diagnostic.message}`;
}

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

function analysisCompilerOptions(projectOptions = {}) {
    return Object.assign({}, projectOptions, {
        target: ts.ScriptTarget.ES2017,
        module: ts.ModuleKind.CommonJS,
        sourceMap: true,
        inlineSourceMap: false,
        inlineSources: false,
        declaration: false,
        declarationMap: false,
        emitDeclarationOnly: false,
        noEmit: false,
        noEmitOnError: false,
        outFile: undefined,
        outDir: undefined,
        removeComments: false,
        importHelpers: true,
        noEmitHelpers: false,
        experimentalDecorators: projectOptions.experimentalDecorators !== false,
        emitDecoratorMetadata: Boolean(projectOptions.emitDecoratorMetadata),
        useDefineForClassFields: Boolean(projectOptions.useDefineForClassFields),
        esModuleInterop: projectOptions.esModuleInterop !== false,
        allowSyntheticDefaultImports: projectOptions.allowSyntheticDefaultImports !== false,
        jsx: projectOptions.jsx || ts.JsxEmit.React,
        allowJs: Boolean(projectOptions.allowJs),
        checkJs: false,
        incremental: false,
        composite: false,
        tsBuildInfoFile: undefined,
    });
}

function findProjectConfig(fileName) {
    if (!fileName || fileName === 'stdin') return null;
    return ts.findConfigFile(path.dirname(normalize(fileName)), ts.sys.fileExists, 'tsconfig.json') || null;
}

function parseProjectConfig(configPath) {
    const loaded = ts.readConfigFile(configPath, ts.sys.readFile);
    if (loaded.error) {
        return { errors: [loaded.error], fileNames: [], options: {}, projectReferences: [] };
    }
    return ts.parseJsonConfigFileContent(
        loaded.config,
        ts.sys,
        path.dirname(configPath),
        undefined,
        configPath,
    );
}

function collectDeclarationMetadata(program, sourceFile) {
    const checker = program.getTypeChecker();
    const functions = [];
    const callSites = [];
    const frameworkEntrypoints = [];

    function isCallable(type) {
        if (!type) return false;
        if (type.getCallSignatures().length > 0) return true;
        return Boolean(type.types && type.types.some(isCallable));
    }

    function callbackParameterTypes(type) {
        if (!type) return [];
        const signatures = type.getCallSignatures();
        if (signatures.length) {
            return signatures.map((signature) => signature.parameters.map((parameter) => {
                const declaration = parameter.valueDeclaration || parameter.declarations && parameter.declarations[0];
                return checker.typeToString(checker.getTypeOfSymbolAtLocation(parameter, declaration || sourceFile));
            }));
        }
        if (type.types) return type.types.flatMap(callbackParameterTypes);
        return [];
    }

    function callableProperties(type) {
        if (!type) return [];
        const properties = [];
        for (const property of checker.getPropertiesOfType(type)) {
            const declaration = property.valueDeclaration || property.declarations && property.declarations[0];
            const propertyType = checker.getTypeOfSymbolAtLocation(property, declaration || sourceFile);
            if (isCallable(propertyType)) {
                properties.push({
                    name: property.getName(),
                    parameters: callbackParameterTypes(propertyType),
                });
            }
        }
        if (type.types) {
            for (const member of type.types) properties.push(...callableProperties(member));
        }
        return properties.filter((property, index, all) =>
            all.findIndex((candidate) => candidate.name === property.name) === index);
    }

    function isExported(node) {
        return Boolean(node.modifiers && node.modifiers.some((modifier) =>
            modifier.kind === ts.SyntaxKind.ExportKeyword || modifier.kind === ts.SyntaxKind.DefaultKeyword));
    }

    function addFunction(node, name, exported = false) {
        if (!node || !node.parameters) return;
        const signature = checker.getSignatureFromDeclaration(node);
        let returnType = 'unknown';
        if (signature) {
            returnType = checker.typeToString(checker.getReturnTypeOfSignature(signature));
        }
        const parameters = node.parameters.map((parameter, index) => {
            const type = checker.getTypeAtLocation(parameter);
            return {
                index,
                name: parameter.name && parameter.name.getText(sourceFile),
                type: checker.typeToString(type),
                callback: isCallable(type),
            };
        });
        functions.push({
            name: name || '<anonymous>',
            exported,
            returnType,
            promiseLike: /^(?:Promise|PromiseLike)</.test(returnType),
            parameters,
        });
        if (exported && ['handler', 'lambdaHandler', 'scheduled', 'fetch'].includes(name)) {
            frameworkEntrypoints.push(name);
        }
    }

    function visit(node) {
        if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) {
            addFunction(node, node.name && node.name.getText(sourceFile), isExported(node));
        } else if (ts.isVariableDeclaration(node) && node.initializer &&
            (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
            const variableStatement = node.parent && node.parent.parent;
            addFunction(node.initializer, node.name.getText(sourceFile),
                Boolean(variableStatement && isExported(variableStatement)));
        }
        if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
            const signature = checker.getResolvedSignature(node);
            if (signature) {
                const declaration = signature.getDeclaration();
                const callbackArguments = [];
                const callbackParameters = {};
                const callbackProperties = [];
                const parameters = declaration && declaration.parameters || [];
                for (let index = 0; index < (node.arguments || []).length; index++) {
                    const parameter = parameters[Math.min(index, parameters.length - 1)];
                    if (parameter) {
                        const parameterType = checker.getTypeAtLocation(parameter);
                        if (isCallable(parameterType)) {
                            callbackArguments.push(index);
                            callbackParameters[index] = callbackParameterTypes(parameterType);
                        }
                        const properties = callableProperties(parameterType);
                        if (properties.length) callbackProperties.push({ argument: index, properties });
                    }
                }
                const returnType = checker.typeToString(checker.getReturnTypeOfSignature(signature));
                if (callbackArguments.length || callbackProperties.length || /^(?:Promise|PromiseLike)</.test(returnType)) {
                    const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
                    callSites.push({
                        line: position.line + 1,
                        column: position.character,
                        callbackArguments,
                        callbackParameters,
                        callbackProperties,
                        returnType,
                        promiseLike: /^(?:Promise|PromiseLike)</.test(returnType),
                    });
                }
            }
        }
        ts.forEachChild(node, visit);
    }

    visit(sourceFile);
    return { functions, callSites, frameworkEntrypoints };
}

class TypeScriptProjectCompiler {
    constructor() {
        this.projects = new Map();
        this.outputs = new Map();
        this.compiling = new Set();
    }

    compileFile(fileName, sourceCode) {
        const compiler = activateProjectTypeScript(fileName);
        if (isArkTSFile(fileName)) {
            const record = this.transpileIsolated(normalizeArkTSSource(sourceCode), `${fileName}.ts`);
            record.compiler = compiler;
            record.arktsProject = discoverArkTSProject(fileName);
            return record;
        }
        if (!fileName || fileName === 'stdin' || !fs.existsSync(fileName)) {
            return this.transpileIsolated(sourceCode, fileName || 'stdin');
        }

        const absoluteFile = normalize(fileName);
        const configPath = findProjectConfig(absoluteFile);
        this.compileProject(configPath, absoluteFile);
        const record = this.outputs.get(absoluteFile) || this.transpileIsolated(sourceCode, absoluteFile);
        record.compiler = compiler;
        return record;
    }

    compileProject(configPath, requestedFile = null) {
        const projectKey = configPath ? normalize(configPath) : `inferred:${normalize(requestedFile)}`;
        if (this.projects.has(projectKey) || this.compiling.has(projectKey)) {
            return this.projects.get(projectKey);
        }
        this.compiling.add(projectKey);

        let parsed;
        if (configPath) {
            parsed = parseProjectConfig(configPath);
        } else {
            parsed = {
                errors: [],
                fileNames: [normalize(requestedFile)],
                options: {
                    moduleResolution: ts.ModuleResolutionKind.Node10,
                    resolveJsonModule: true,
                },
                projectReferences: [],
            };
        }

        const rootNames = parsed.fileNames.slice();
        if (requestedFile && isRuntimeSourceFile(requestedFile) && !rootNames.map(normalize).includes(normalize(requestedFile))) {
            rootNames.push(normalize(requestedFile));
        }

        for (const reference of parsed.projectReferences || []) {
            let referenceConfig = ts.resolveProjectReferencePath ?
                ts.resolveProjectReferencePath(reference) : path.resolve(reference.path, 'tsconfig.json');
            if (fs.existsSync(referenceConfig)) {
                this.compileProject(referenceConfig);
            }
        }

        const options = analysisCompilerOptions(parsed.options);
        const program = ts.createProgram({
            rootNames,
            options,
            projectReferences: parsed.projectReferences,
        });
        const diagnostics = [
            ...(parsed.errors || []),
            ...program.getConfigFileParsingDiagnostics(),
            ...program.getSyntacticDiagnostics(),
            ...program.getOptionsDiagnostics(),
            ...program.getSemanticDiagnostics(),
        ].map(formatDiagnostic);

        const project = {
            configPath: configPath ? normalize(configPath) : null,
            diagnostics,
            files: [],
        };
        this.projects.set(projectKey, project);

        for (const sourceFile of program.getSourceFiles()) {
            const sourcePath = normalize(sourceFile.fileName);
            if (!isRuntimeSourceFile(sourcePath) || sourceFile.isDeclarationFile) continue;
            const emitted = { code: null, sourceMap: null };
            const emitResult = program.emit(
                sourceFile,
                (outputName, data) => {
                    if (/\.map$/i.test(outputName)) {
                        try {
                            emitted.sourceMap = JSON.parse(data);
                        } catch (_) {
                            emitted.sourceMap = null;
                        }
                    } else if (/\.[cm]?js$/i.test(outputName)) {
                        emitted.code = data;
                    }
                },
            );
            const fileDiagnostics = (emitResult.diagnostics || []).map(formatDiagnostic);
            if (emitted.code != null) {
                const declarationMetadata = collectDeclarationMetadata(program, sourceFile);
                const entrypointCalls = declarationMetadata.frameworkEntrypoints
                    .map((name) => `\nOPGen_markTaintCall(exports.${name});`)
                    .join('');
                const record = {
                    code: emitted.code.replace(/^\/\/# sourceMappingURL=.*$/m, '') + entrypointCalls,
                    sourceMap: emitted.sourceMap,
                    diagnostics: [...diagnostics, ...fileDiagnostics],
                    projectConfig: project.configPath,
                    declarationMetadata,
                    projectLevel: true,
                    compiler: { path: activeTypeScriptPath, version: ts.version || 'unknown' },
                };
                this.outputs.set(sourcePath, record);
                project.files.push(sourcePath);
            }
        }

        this.compiling.delete(projectKey);
        return project;
    }

    transpileIsolated(sourceCode, fileName) {
        const result = ts.transpileModule(sourceCode, {
            fileName,
            reportDiagnostics: true,
            compilerOptions: analysisCompilerOptions({}),
        });
        return {
            code: result.outputText.replace(/^\/\/# sourceMappingURL=.*$/m, ''),
            diagnostics: (result.diagnostics || []).map(formatDiagnostic),
            sourceMap: result.sourceMapText ? JSON.parse(result.sourceMapText) : null,
            projectConfig: null,
            declarationMetadata: { functions: [], callSites: [] },
            projectLevel: false,
        };
    }
}

function remapAstLocations(root, rawSourceMap, declarationMetadata = null) {
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
            if (originalStart) {
                value.loc = { start: originalStart, end: originalEnd };
            }
        }
        for (const key of Object.keys(value)) {
            if (key !== 'loc' && key !== 'range' && key !== 'tokens' && key !== 'comments' &&
                key !== 'probejsGeneratedLoc') {
                visit(value[key]);
            }
        }
    }

    visit(root);

    const callSites = declarationMetadata && declarationMetadata.callSites || [];
    if (callSites.length) {
        const callNodes = [];
        const collectCalls = (value) => {
            if (!value || typeof value !== 'object') return;
            if ((value.type === 'CallExpression' || value.type === 'NewExpression') && value.loc) {
                callNodes.push(value);
            }
            for (const key of Object.keys(value)) {
                if (!['loc', 'range', 'tokens', 'comments', 'probejsGeneratedLoc'].includes(key)) {
                    collectCalls(value[key]);
                }
            }
        };
        collectCalls(root);
        for (const callSite of callSites) {
            const candidates = callNodes.filter((node) => node.loc.start.line === callSite.line);
            if (!candidates.length) continue;
            candidates.sort((left, right) =>
                Math.abs(left.loc.start.column - callSite.column) - Math.abs(right.loc.start.column - callSite.column));
            candidates[0].probejsCallbackArguments = callSite.callbackArguments;
            candidates[0].probejsCallbackParameters = callSite.callbackParameters;
            candidates[0].probejsCallbackProperties = callSite.callbackProperties;
            candidates[0].probejsPromiseLike = callSite.promiseLike;
            candidates[0].probejsReturnType = callSite.returnType;
        }
    }
}

const projectCompiler = new TypeScriptProjectCompiler();

module.exports = {
    DECLARATION_FILE_RE,
    TYPESCRIPT_EXTENSIONS,
    TypeScriptProjectCompiler,
    isRuntimeSourceFile,
    isArkTSFile,
    isTypeScriptFile,
    normalizeArkTSSource,
    discoverArkTSProject,
    projectCompiler,
    diagnosticText,
    loadJavaScriptSourceMap,
    remapAstLocations,
};
