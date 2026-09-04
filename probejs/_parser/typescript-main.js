#!/usr/bin/env node

/**
 * TypeScript project frontend for probejs.
 *
 * This frontend parses original TypeScript source into an ESTree-compatible
 * tree, removes type-only syntax in memory, adds the small runtime abstractions
 * required by the existing OPG, and delegates only the stable ESTree-to-CSV
 * encoding step to main.js.  It never asks TypeScript to emit JavaScript.
 */

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');
const ts = require('typescript');
const { parseAndGenerateServices } = require('@typescript-eslint/typescript-estree');
const { searchModule } = require('./search.js');
const program = require('commander');

const TS_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts']);
const RUNTIME_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']);
const TYPE_ONLY_NODES = new Set([
    'TSInterfaceDeclaration',
    'TSTypeAliasDeclaration',
    'TSDeclareFunction',
    'TSImportType',
    'TSIndexSignature',
]);
const TYPE_WRAPPERS = new Set([
    'TSAsExpression',
    'TSTypeAssertion',
    'TSNonNullExpression',
    'TSSatisfiesExpression',
    'TSInstantiationExpression',
]);
const ENTRYPOINT_NAMES = new Set(['handler', 'lambdaHandler', 'scheduled', 'fetch']);
const TYPE_FIELDS = new Set([
    'typeAnnotation', 'typeArguments', 'typeParameters', 'returnType', 'superTypeArguments',
    'implements', 'accessibility', 'abstract', 'declare', 'definite', 'optional', 'override',
    'readonly', 'in', 'out', 'const', 'exportKind', 'importKind', 'assertions', 'attributes',
]);

program
    .version('1.0.0')
    .usage('<filename or directory> [options]')
    .arguments('<filename or directory>')
    .action(function (input) { this.input = input; })
    .option('-o, --output <path>', 'Output directory, or - for stdout')
    .option('-n, --start <number>', 'Starting node number')
    .option('--style <php/c>', 'CSV style', 'php')
    .option('--delimiter <comma/tab>', 'CSV delimiter', 'tab')
    .option('-e, --expression', 'Parse stdin as an expression')
    .option('--typescript', 'Parse stdin as TypeScript')
    .parse(process.argv);

if (!program.input) {
    console.error('A TypeScript filename, directory, or - is required.');
    process.exit(1);
}

function normalizePath(fileName) {
    return path.normalize(path.resolve(fileName));
}

function isDeclarationFile(fileName) {
    return /\.d\.[cm]?ts$/i.test(fileName);
}

function isTypeScriptRuntimeFile(fileName) {
    return TS_EXTENSIONS.has(path.extname(fileName).toLowerCase()) && !isDeclarationFile(fileName);
}

function diagnosticRecord(diagnostic) {
    const record = {
        source: 'typescript',
        code: `TS${diagnostic.code}`,
        category: String(ts.DiagnosticCategory[diagnostic.category] || 'error').toLowerCase(),
        message: ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'),
        file: null,
        line: null,
        column: null,
    };
    if (diagnostic.file && diagnostic.start !== undefined) {
        const position = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
        record.file = diagnostic.file.fileName;
        record.line = position.line + 1;
        record.column = position.character + 1;
    }
    return record;
}

function collectFiles(directory) {
    const files = [];
    function visit(current) {
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            if (entry.isDirectory()) {
                if (!['node_modules', '.git', 'dist', 'build', 'coverage'].includes(entry.name)) {
                    visit(path.join(current, entry.name));
                }
            } else if (isTypeScriptRuntimeFile(entry.name)) {
                files.push(normalizePath(path.join(current, entry.name)));
            }
        }
    }
    visit(directory);
    return files;
}

function collectJavaScriptFiles(directory) {
    const files = [];
    function visit(current) {
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            if (entry.isDirectory()) {
                if (!['node_modules', '.git', 'dist', 'build', 'coverage'].includes(entry.name)) {
                    visit(path.join(current, entry.name));
                }
            } else if (['.js', '.jsx', '.mjs', '.cjs'].includes(path.extname(entry.name).toLowerCase())) {
                files.push(normalizePath(path.join(current, entry.name)));
            }
        }
    }
    visit(directory);
    return files;
}

function loadProject(inputPath, entryOverride = null, directoryRoot = null) {
    const absoluteInput = normalizePath(inputPath);
    const physicalDirectory = fs.statSync(absoluteInput).isDirectory();
    const directoryInput = Boolean(directoryRoot) || physicalDirectory;
    const searchDirectory = physicalDirectory ? absoluteInput : path.dirname(absoluteInput);
    const configPath = ts.findConfigFile(searchDirectory, ts.sys.fileExists, 'tsconfig.json') || null;
    let rootNames;
    let options;
    let projectReferences = [];
    let configErrors = [];

    if (configPath) {
        const loaded = ts.readConfigFile(configPath, ts.sys.readFile);
        if (loaded.error) {
            configErrors.push(loaded.error);
            rootNames = entryOverride || (physicalDirectory ? collectFiles(absoluteInput) : [absoluteInput]);
            options = {};
        } else {
            const parsed = ts.parseJsonConfigFileContent(
                loaded.config,
                ts.sys,
                path.dirname(configPath),
                { noEmit: true },
                configPath,
            );
            rootNames = parsed.fileNames;
            options = parsed.options;
            projectReferences = parsed.projectReferences || [];
            configErrors.push(...(parsed.errors || []));
        }
    } else {
        rootNames = entryOverride || (physicalDirectory ? collectFiles(absoluteInput) : [absoluteInput]);
        options = {
            target: ts.ScriptTarget.ESNext,
            module: ts.ModuleKind.NodeNext,
            moduleResolution: ts.ModuleResolutionKind.NodeNext,
            allowJs: true,
            checkJs: false,
            resolveJsonModule: true,
            jsx: ts.JsxEmit.React,
            noEmit: true,
        };
    }

    if (!physicalDirectory && !rootNames.map(normalizePath).includes(absoluteInput)) {
        rootNames.push(absoluteInput);
    }
    options = Object.assign({}, options, { noEmit: true, noEmitOnError: false });
    const compilerHost = ts.createCompilerHost(options, true);
    const tsProgram = ts.createProgram({ rootNames, options, projectReferences, host: compilerHost });
    const diagnostics = [
        ...configErrors,
        ...tsProgram.getConfigFileParsingDiagnostics(),
        ...tsProgram.getSyntacticDiagnostics(),
        ...tsProgram.getOptionsDiagnostics(),
        ...tsProgram.getSemanticDiagnostics(),
    ].map(diagnosticRecord);

    const projectRoot = directoryRoot ? normalizePath(directoryRoot) : absoluteInput;
    const entryFiles = entryOverride || (physicalDirectory ? rootNames.filter((file) =>
        isTypeScriptRuntimeFile(file) && normalizePath(file).startsWith(absoluteInput + path.sep)) : [absoluteInput]);
    return {
        program: tsProgram,
        options,
        configPath: configPath ? normalizePath(configPath) : null,
        diagnostics,
        entryFiles,
        directoryInput,
        inputPath: projectRoot,
    };
}

function loadProjects(inputPath) {
    const absoluteInput = normalizePath(inputPath);
    if (!fs.statSync(absoluteInput).isDirectory()) return [loadProject(absoluteInput)];
    const groups = new Map();
    for (const fileName of collectFiles(absoluteInput)) {
        const configPath = ts.findConfigFile(path.dirname(fileName), ts.sys.fileExists, 'tsconfig.json') || '__inferred__';
        if (!groups.has(configPath)) groups.set(configPath, []);
        groups.get(configPath).push(fileName);
    }
    return [...groups.values()].map((entries) => loadProject(entries[0], entries, absoluteInput));
}

function locationFrom(origin) {
    return origin && origin.loc ? {
        start: { line: origin.loc.start.line, column: origin.loc.start.column },
        end: { line: origin.loc.end.line, column: origin.loc.end.column },
    } : null;
}

function withOrigin(node, origin, generated = true) {
    if (origin && origin.range) node.range = [origin.range[0], origin.range[1]];
    if (origin && origin.loc) node.loc = locationFrom(origin);
    if (generated && node.loc) {
        node.probejsGenerated = true;
        node.probejsGeneratedLoc = locationFrom(node);
    }
    return node;
}

function identifier(name, origin, generated = true) {
    const node = withOrigin({ type: 'Identifier', name }, origin, generated);
    if (generated) node.probejsCode = name;
    return node;
}

function literal(value, origin, generated = true) {
    const raw = typeof value === 'string' ? JSON.stringify(value) : String(value);
    const node = withOrigin({ type: 'Literal', value, raw }, origin, generated);
    if (generated) node.probejsCode = raw;
    return node;
}

function member(object, property, computed, origin) {
    const propertyNode = typeof property === 'string' ?
        (computed ? literal(property, origin) : identifier(property, origin)) : property;
    const node = withOrigin({ type: 'MemberExpression', object, property: propertyNode, computed: Boolean(computed), optional: false }, origin);
    const objectCode = object.probejsCode || object.name || '';
    const propertyCode = propertyNode.probejsCode || propertyNode.name || propertyNode.raw || '';
    node.probejsCode = computed ? `${objectCode}[${propertyCode}]` : `${objectCode}.${propertyCode}`;
    return node;
}

function call(callee, args, origin, modulePath = null) {
    const node = withOrigin({ type: 'CallExpression', callee, arguments: args, optional: false }, origin);
    const calleeCode = callee.probejsCode || callee.name || '';
    node.probejsCode = `${calleeCode}(${args.map((arg) => arg.probejsCode || arg.name || arg.raw || '').join(', ')})`;
    if (modulePath) node.probejsModulePath = modulePath;
    return node;
}

function assignment(left, right, origin) {
    const node = withOrigin({ type: 'AssignmentExpression', operator: '=', left, right }, origin);
    node.probejsCode = `${left.probejsCode || left.name || ''} = ${right.probejsCode || right.name || right.raw || ''}`;
    return node;
}

function expressionStatement(expression, origin) {
    return withOrigin({ type: 'ExpressionStatement', expression }, origin);
}

function variableDeclaration(nameOrPattern, init, kind, origin) {
    const id = typeof nameOrPattern === 'string' ? identifier(nameOrPattern, origin) : nameOrPattern;
    const declaration = withOrigin({ type: 'VariableDeclarator', id, init }, origin);
    return withOrigin({ type: 'VariableDeclaration', declarations: [declaration], kind: kind || 'const' }, origin);
}

function blockStatement(body, origin) {
    return withOrigin({ type: 'BlockStatement', body }, origin);
}

function requireCall(specifier, origin, modulePath) {
    return call(identifier('require', origin), [literal(specifier, origin)], origin, modulePath);
}

function bindingNames(pattern, result = []) {
    if (!pattern) return result;
    if (pattern.type === 'Identifier') result.push(pattern.name);
    else if (pattern.type === 'RestElement') bindingNames(pattern.argument, result);
    else if (pattern.type === 'AssignmentPattern') bindingNames(pattern.left, result);
    else if (pattern.type === 'ArrayPattern') {
        for (const element of pattern.elements || []) bindingNames(element, result);
    } else if (pattern.type === 'ObjectPattern') {
        for (const property of pattern.properties || []) {
            bindingNames(property.type === 'RestElement' ? property.argument : property.value, result);
        }
    }
    return result;
}

function declarationNames(declaration) {
    if (!declaration) return [];
    if (declaration.type === 'VariableDeclaration') {
        return declaration.declarations.flatMap((item) => bindingNames(item.id));
    }
    if ((declaration.type === 'FunctionDeclaration' || declaration.type === 'ClassDeclaration') && declaration.id) {
        return [declaration.id.name];
    }
    if ((declaration.type === 'TSEnumDeclaration' || declaration.type === 'TSModuleDeclaration') && declaration.id) {
        return [declaration.id.name || declaration.id.value];
    }
    return [];
}

function isCallable(type) {
    if (!type) return false;
    if (type.getCallSignatures().length) return true;
    return Boolean(type.isUnionOrIntersection && type.isUnionOrIntersection() && type.types.some(isCallable));
}

function callbackParameterTypes(checker, type, location) {
    if (!type) return [];
    const signatures = type.getCallSignatures();
    if (signatures.length) {
        return signatures.map((signature) => signature.parameters.map((parameter) => {
            const parameterType = checker.getTypeOfSymbolAtLocation(parameter, location);
            return checker.typeToString(parameterType);
        }));
    }
    if (type.isUnionOrIntersection && type.isUnionOrIntersection()) {
        return type.types.flatMap((item) => callbackParameterTypes(checker, item, location));
    }
    return [];
}

function callableProperties(checker, type, location) {
    if (!type) return [];
    const properties = [];
    for (const property of checker.getPropertiesOfType(checker.getApparentType(type))) {
        const propertyType = checker.getTypeOfSymbolAtLocation(property, location);
        if (isCallable(propertyType)) {
            properties.push({
                name: property.getName(),
                parameters: callbackParameterTypes(checker, propertyType, location),
            });
        }
    }
    if (type.isUnionOrIntersection && type.isUnionOrIntersection()) {
        for (const item of type.types) properties.push(...callableProperties(checker, item, location));
    }
    return properties.filter((property, index, all) =>
        all.findIndex((candidate) => candidate.name === property.name) === index);
}

function isPromiseLike(checker, type, location) {
    if (!type) return false;
    try {
        if (typeof checker.getPromisedTypeOfPromise === 'function' && checker.getPromisedTypeOfPromise(type)) {
            return true;
        }
    } catch (_) {
        // Some compiler versions throw for unresolved/error types.
    }
    const then = checker.getPropertyOfType(checker.getApparentType(type), 'then');
    return Boolean(then && isCallable(checker.getTypeOfSymbolAtLocation(then, location)));
}

function annotateSemantics(ast, services) {
    const tsProgram = services && services.program;
    const nodeMap = services && services.esTreeNodeToTSNodeMap;
    if (!tsProgram || !nodeMap) return;
    const checker = tsProgram.getTypeChecker();
    const seen = new Set();

    function visit(node) {
        if (!node || typeof node !== 'object' || seen.has(node)) return;
        seen.add(node);
        if (node.type === 'CallExpression' || node.type === 'NewExpression') {
            const tsNode = nodeMap.get(node);
            if (tsNode) {
                try {
                    const signature = checker.getResolvedSignature(tsNode);
                    if (signature) {
                        const callbackArguments = [];
                        const callbackParameters = {};
                        const callbackProperties = [];
                        const parameters = signature.parameters || [];
                        const declaration = signature.getDeclaration && signature.getDeclaration();
                        const rest = Boolean(declaration && declaration.parameters && declaration.parameters.length &&
                            declaration.parameters[declaration.parameters.length - 1].dotDotDotToken);
                        for (let index = 0; index < (node.arguments || []).length; index++) {
                            if (!parameters.length) break;
                            const parameterIndex = index < parameters.length ? index : (rest ? parameters.length - 1 : -1);
                            if (parameterIndex < 0) continue;
                            const parameter = parameters[parameterIndex];
                            let parameterType = checker.getTypeOfSymbolAtLocation(parameter, tsNode);
                            if (rest && index >= parameters.length - 1 && checker.getIndexTypeOfType) {
                                const elementType = checker.getIndexTypeOfType(parameterType, ts.IndexKind.Number);
                                if (elementType) parameterType = elementType;
                            }
                            if (isCallable(parameterType)) {
                                callbackArguments.push(index);
                                callbackParameters[index] = callbackParameterTypes(checker, parameterType, tsNode);
                            }
                            const properties = node.arguments[index] && node.arguments[index].type === 'ObjectExpression' ?
                                callableProperties(checker, parameterType, tsNode) : [];
                            if (properties.length) callbackProperties.push({ argument: index, properties });
                        }
                        const returnType = checker.getReturnTypeOfSignature(signature);
                        if (callbackArguments.length || callbackProperties.length || isPromiseLike(checker, returnType, tsNode)) {
                            node.probejsCallbackArguments = callbackArguments;
                            node.probejsCallbackParameters = callbackParameters;
                        }
                        if (callbackProperties.length) node.probejsCallbackProperties = callbackProperties;
                        node.probejsPromiseLike = isPromiseLike(checker, returnType, tsNode);
                        node.probejsReturnType = checker.typeToString(returnType);
                    }
                } catch (_) {
                    // Type errors must not prevent conservative runtime analysis.
                }
            }
        }
        for (const [key, value] of Object.entries(node)) {
            if (!['loc', 'range', 'parent', 'tokens', 'comments'].includes(key)) {
                if (Array.isArray(value)) value.forEach(visit);
                else visit(value);
            }
        }
    }
    visit(ast);
}

class RuntimeNormalizer {
    constructor(fileName, sourceCode, compilerOptions, resolveModule) {
        this.fileName = fileName;
        this.sourceCode = sourceCode;
        this.compilerOptions = compilerOptions;
        this.resolveModule = resolveModule;
        this.exportedEntrypoints = new Set();
        this.syntheticClassCounter = 0;
    }

    normalizeProgram(ast) {
        const body = [];
        for (const statement of ast.body || []) body.push(...this.normalizeStatement(statement));
        for (const name of this.exportedEntrypoints) {
            const target = member(identifier('exports', ast), name, false, ast);
            body.push(expressionStatement(call(identifier('OPGen_markTaintCall', ast), [target], ast), ast));
        }
        ast.body = body;
        ast.sourceType = 'script';
        this.stripTypeFields(ast);
        return ast;
    }

    normalizeStatement(node, namespace = null) {
        if (!node || TYPE_ONLY_NODES.has(node.type)) return [];
        switch (node.type) {
            case 'ImportDeclaration':
                return this.normalizeImport(node);
            case 'ExportNamedDeclaration':
                return this.normalizeNamedExport(node, namespace);
            case 'ExportDefaultDeclaration':
                return this.normalizeDefaultExport(node, namespace);
            case 'ExportAllDeclaration':
                return this.normalizeExportAll(node, namespace);
            case 'TSEnumDeclaration':
                return this.normalizeEnum(node, namespace);
            case 'TSModuleDeclaration':
                return this.normalizeNamespace(node);
            case 'TSImportEqualsDeclaration':
                return this.normalizeImportEquals(node);
            case 'TSExportAssignment':
                return [expressionStatement(assignment(
                    member(identifier('module', node), 'exports', false, node),
                    this.normalizeNode(node.expression), node), node)];
            case 'TSNamespaceExportDeclaration':
                return [];
            case 'VariableDeclaration':
                if (node.declare) return [];
                node.declarations = node.declarations.map((declaration) => this.normalizeNode(declaration)).filter(Boolean);
                this.stripTypeFields(node);
                return node.declarations.length ? [node] : [];
            case 'FunctionDeclaration':
                if (node.declare || !node.body) return [];
                this.normalizeFunction(node);
                return [node];
            case 'ClassDeclaration':
                if (node.declare) return [];
                return this.normalizeClass(node);
            case 'BlockStatement': {
                const body = [];
                for (const statement of node.body || []) body.push(...this.normalizeStatement(statement, namespace));
                node.body = body;
                this.stripTypeFields(node);
                return [node];
            }
            default: {
                const normalized = this.normalizeNode(node);
                return normalized ? (Array.isArray(normalized) ? normalized : [normalized]) : [];
            }
        }
    }

    normalizeNode(node) {
        if (!node || typeof node !== 'object') return node;
        if (TYPE_ONLY_NODES.has(node.type)) return null;
        if (TYPE_WRAPPERS.has(node.type)) return this.normalizeNode(node.expression);
        switch (node.type) {
            case 'Identifier': {
                if (node.range && node.loc && typeof node.name === 'string') {
                    node.range[1] = node.range[0] + node.name.length;
                    node.loc.end = {
                        line: node.loc.start.line,
                        column: node.loc.start.column + node.name.length,
                    };
                }
                this.stripTypeFields(node);
                return node;
            }
            case 'ChainExpression':
                return this.normalizeNode(node.expression);
            case 'TSParameterProperty':
                return this.normalizeNode(node.parameter);
            case 'PrivateIdentifier':
                return identifier(node.name, node, false);
            case 'TSQualifiedName':
                return member(this.normalizeNode(node.left), this.normalizeNode(node.right), false, node);
            case 'FunctionExpression':
            case 'ArrowFunctionExpression':
                this.normalizeFunction(node);
                return node;
            case 'ClassExpression': {
                const values = this.normalizeClass(node);
                if (values.length === 1) return values[0];
                const className = values[0].id.name;
                const body = [variableDeclaration(className, values[0], 'const', node),
                    ...values.slice(1),
                    withOrigin({ type: 'ReturnStatement', argument: identifier(className, node) }, node)];
                const factory = withOrigin({
                    type: 'ArrowFunctionExpression', id: null, params: [], generator: false,
                    async: false, expression: false, body: blockStatement(body, node),
                }, node);
                return call(factory, [], node);
            }
            case 'JSXElement':
                return this.normalizeJsxElement(node);
            case 'JSXFragment':
                return this.normalizeJsxFragment(node);
            case 'ImportExpression': {
                const source = this.normalizeNode(node.source);
                const specifier = source && typeof source.value === 'string' ? source.value : null;
                return call(identifier('require', node), [source], node,
                    specifier ? this.resolveModule(specifier) : null);
            }
            case 'TaggedTemplateExpression':
                return call(this.normalizeNode(node.tag), [this.normalizeNode(node.quasi)], node);
            case 'CallExpression':
            case 'NewExpression': {
                node.callee = this.normalizeNode(node.callee);
                node.arguments = (node.arguments || []).map((argument) => this.normalizeNode(argument)).filter(Boolean);
                node.optional = false;
                if (node.callee && node.callee.type === 'Identifier' && node.callee.name === 'require' &&
                    node.arguments[0] && typeof node.arguments[0].value === 'string') {
                    node.probejsModulePath = this.resolveModule(node.arguments[0].value);
                }
                this.stripTypeFields(node);
                return node;
            }
            case 'MemberExpression':
                node.object = this.normalizeNode(node.object);
                node.property = this.normalizeNode(node.property);
                node.optional = false;
                this.stripTypeFields(node);
                return node;
            case 'LogicalExpression':
                if (node.operator === '??') node.operator = '||';
                break;
            case 'MetaProperty':
                return identifier(`${node.meta.name}.${node.property.name}`, node);
            case 'PropertyDefinition':
            case 'AccessorProperty':
                return null;
        }

        if (node.type === 'Program' || node.type === 'BlockStatement') {
            const body = [];
            for (const statement of node.body || []) body.push(...this.normalizeStatement(statement));
            node.body = body;
        } else {
            for (const [key, value] of Object.entries(node)) {
                if (this.isTypeField(key) || ['loc', 'range', 'tokens', 'comments'].includes(key)) continue;
                if (Array.isArray(value)) {
                    node[key] = value.map((item) => this.normalizeNode(item)).filter(Boolean);
                } else if (value && typeof value === 'object' && value.type) {
                    node[key] = this.normalizeNode(value);
                }
            }
        }
        this.stripTypeFields(node);
        return node;
    }

    isTypeField(key) {
        return TYPE_FIELDS.has(key);
    }

    stripTypeFields(node) {
        if (!node || typeof node !== 'object') return;
        for (const key of Object.keys(node)) {
            if (this.isTypeField(key) || key === 'decorators') delete node[key];
        }
    }

    normalizeFunction(node) {
        node.params = (node.params || []).map((parameter) => this.normalizeNode(parameter)).filter(Boolean);
        if (node.body && node.body.type === 'BlockStatement') {
            node.body = this.normalizeStatement(node.body)[0];
        } else {
            node.body = this.normalizeNode(node.body);
        }
        this.stripTypeFields(node);
    }

    normalizeImport(node) {
        if (node.importKind === 'type') return [];
        const specifier = node.source.value;
        const resolved = this.resolveModule(specifier);
        const runtimeSpecifiers = (node.specifiers || []).filter((item) => item.importKind !== 'type');
        if (!runtimeSpecifiers.length) {
            if ((node.specifiers || []).length) return [];
            return [expressionStatement(requireCall(specifier, node, resolved), node)];
        }
        const statements = [];
        for (const item of runtimeSpecifiers) {
            let init = requireCall(specifier, item, resolved);
            if (item.type === 'ImportDefaultSpecifier') {
                if (resolved && isTypeScriptRuntimeFile(resolved)) init = member(init, 'default', false, item);
            } else if (item.type === 'ImportSpecifier') {
                const imported = item.imported.name === undefined ? item.imported.value : item.imported.name;
                init = member(init, imported, false, item);
            }
            statements.push(variableDeclaration(this.normalizeNode(item.local), init, 'const', item));
        }
        return statements;
    }

    normalizeImportEquals(node) {
        if (node.importKind === 'type') return [];
        let init;
        if (node.moduleReference.type === 'TSExternalModuleReference') {
            const specifier = node.moduleReference.expression.value;
            init = requireCall(specifier, node, this.resolveModule(specifier));
        } else {
            init = this.normalizeNode(node.moduleReference);
        }
        return [variableDeclaration(this.normalizeNode(node.id), init, 'const', node)];
    }

    exportTarget(name, origin, namespace) {
        const target = namespace ? identifier(namespace, origin) : identifier('exports', origin);
        return member(target, name, false, origin);
    }

    normalizeNamedExport(node, namespace) {
        if (node.exportKind === 'type') return [];
        const statements = [];
        if (node.declaration) {
            const originalDeclaration = node.declaration;
            const normalizedDeclarations = this.normalizeStatement(originalDeclaration, namespace);
            statements.push(...normalizedDeclarations);
            for (const name of declarationNames(originalDeclaration)) {
                statements.push(expressionStatement(
                    assignment(this.exportTarget(name, node, namespace), identifier(name, node), node), node));
                if (!namespace && ENTRYPOINT_NAMES.has(name) &&
                    (originalDeclaration.type === 'FunctionDeclaration' ||
                     originalDeclaration.type === 'VariableDeclaration')) {
                    this.exportedEntrypoints.add(name);
                }
            }
        }
        for (const specifier of node.specifiers || []) {
            if (specifier.exportKind === 'type') continue;
            const exported = specifier.exported.name === undefined ? specifier.exported.value : specifier.exported.name;
            const local = specifier.local ?
                (specifier.local.name === undefined ? specifier.local.value : specifier.local.name) : null;
            let value;
            if (specifier.type === 'ExportNamespaceSpecifier' && node.source) {
                value = requireCall(node.source.value, node, this.resolveModule(node.source.value));
            } else if (node.source) {
                value = member(requireCall(node.source.value, node, this.resolveModule(node.source.value)), local, false, node);
            } else {
                value = identifier(local, specifier, false);
            }
            statements.push(expressionStatement(
                assignment(this.exportTarget(exported, specifier, namespace), value, specifier), specifier));
            if (!namespace && ENTRYPOINT_NAMES.has(exported)) this.exportedEntrypoints.add(exported);
        }
        return statements;
    }

    normalizeDefaultExport(node, namespace) {
        if (node.exportKind === 'type') return [];
        const declaration = node.declaration;
        const statements = [];
        let value;
        if (!namespace && declaration.id && ENTRYPOINT_NAMES.has(declaration.id.name)) {
            this.exportedEntrypoints.add('default');
        }
        if (declaration.type === 'FunctionDeclaration' || declaration.type === 'ClassDeclaration') {
            if (declaration.id) {
                statements.push(...this.normalizeStatement(declaration, namespace));
                value = identifier(declaration.id.name, declaration.id, false);
            } else if (declaration.type === 'FunctionDeclaration') {
                declaration.type = 'FunctionExpression';
                this.normalizeFunction(declaration);
                value = declaration;
            } else {
                declaration.type = 'ClassExpression';
                value = this.normalizeNode(declaration);
            }
        } else {
            value = this.normalizeNode(declaration);
        }
        statements.push(expressionStatement(
            assignment(this.exportTarget('default', node, namespace), value, node), node));
        return statements;
    }

    normalizeExportAll(node, namespace) {
        if (node.exportKind === 'type') return [];
        const target = namespace ? identifier(namespace, node) : identifier('exports', node);
        const objectAssign = member(identifier('Object', node), 'assign', false, node);
        return [expressionStatement(call(objectAssign,
            [target, requireCall(node.source.value, node, this.resolveModule(node.source.value))], node), node)];
    }

    normalizeEnum(node, namespace) {
        if (node.declare) return [];
        const enumName = node.id.name;
        const statements = [variableDeclaration(enumName, withOrigin({
            type: 'ObjectExpression', properties: [],
        }, node), 'const', node)];
        let nextNumber = 0;
        for (const enumMember of node.body.members || node.members || []) {
            const name = enumMember.id.name === undefined ? enumMember.id.value : enumMember.id.name;
            let value;
            if (enumMember.initializer) {
                value = this.normalizeNode(enumMember.initializer);
                if (value.type === 'Literal' && typeof value.value === 'number') nextNumber = value.value + 1;
            } else {
                value = literal(nextNumber++, enumMember);
            }
            statements.push(expressionStatement(
                assignment(member(identifier(enumName, enumMember), name, false, enumMember), value, enumMember),
                enumMember));
        }
        if (namespace) {
            statements.push(expressionStatement(assignment(
                this.exportTarget(enumName, node, namespace), identifier(enumName, node), node), node));
        }
        return statements;
    }

    normalizeNamespace(node) {
        if (node.declare || node.global) return [];
        const namespaceName = node.id.name || node.id.value;
        const statements = [variableDeclaration(namespaceName,
            withOrigin({ type: 'ObjectExpression', properties: [] }, node), 'const', node)];
        if (node.body && node.body.type === 'TSModuleBlock') {
            for (const statement of node.body.body || []) {
                statements.push(...this.normalizeStatement(statement, namespaceName));
            }
        } else if (node.body) {
            statements.push(...this.normalizeNamespace(node.body));
        }
        return statements;
    }

    normalizeClass(node) {
        if (!node.id && node.type === 'ClassExpression') {
            node.id = identifier(`__probejs_class_${this.syntheticClassCounter++}`, node);
        }
        node.superClass = this.normalizeNode(node.superClass);
        const members = [];
        const instanceInitializers = [];
        const staticInitializers = [];
        const decoratorCalls = [];
        let constructor = null;

        for (const item of node.body.body || []) {
            if (item.type === 'TSAbstractMethodDefinition' || item.type === 'TSAbstractPropertyDefinition' ||
                item.type === 'TSEmptyBodyFunctionExpression') {
                continue;
            }
            if (item.type === 'StaticBlock') {
                for (const statement of item.body || []) {
                    staticInitializers.push(...this.normalizeStatement(statement));
                }
                continue;
            }
            if (item.type === 'PropertyDefinition' || item.type === 'AccessorProperty') {
                if (item.declare || !item.value) continue;
                const key = this.normalizeNode(item.key);
                const classReference = node.id ? identifier(node.id.name, item) : null;
                const target = item.static && classReference ? classReference : { type: 'ThisExpression' };
                withOrigin(target, item, !item.static);
                const init = expressionStatement(assignment(
                    member(target, key, Boolean(item.computed), item), this.normalizeNode(item.value), item), item);
                (item.static ? staticInitializers : instanceInitializers).push(init);
                for (const decorator of item.decorators || []) {
                    if (classReference) decoratorCalls.push(expressionStatement(call(
                        this.normalizeNode(decorator.expression), [classReference, literal(key.name || key.value, item)], decorator), decorator));
                }
                continue;
            }
            if (item.type === 'MethodDefinition') {
                if (item.kind === 'constructor') constructor = item;
                const parameterProperties = [];
                for (const rawParameter of item.value.params || []) {
                    if (rawParameter.type === 'TSParameterProperty') {
                        const parameter = rawParameter.parameter;
                        const targetParameter = parameter.type === 'AssignmentPattern' ? parameter.left : parameter;
                        if (targetParameter.type === 'Identifier') {
                            parameterProperties.push(expressionStatement(assignment(
                                member(withOrigin({ type: 'ThisExpression' }, rawParameter), targetParameter.name, false, rawParameter),
                                identifier(targetParameter.name, targetParameter, false), rawParameter), rawParameter));
                        }
                    }
                }
                this.normalizeFunction(item.value);
                if (item.kind === 'constructor') {
                    item.value.body.body.unshift(...parameterProperties);
                }
                item.key = this.normalizeNode(item.key);
                for (const decorator of item.decorators || []) {
                    if (node.id) {
                        const classIdentifier = identifier(node.id.name, decorator);
                        const methodName = item.key.name || item.key.value;
                        decoratorCalls.push(expressionStatement(call(
                            this.normalizeNode(decorator.expression),
                            [classIdentifier, literal(methodName, item)], decorator), decorator));
                        const prototypeMethod = member(
                            member(identifier(node.id.name, item), 'prototype', false, item),
                            methodName, false, item);
                        decoratorCalls.push(expressionStatement(call(
                            identifier('OPGen_markTaintCall', item), [prototypeMethod], item), item));
                    }
                }
                this.stripTypeFields(item);
                members.push(item);
            }
        }

        if (instanceInitializers.length) {
            if (!constructor) {
                const constructorOrigin = node;
                const params = [];
                const body = [];
                if (node.superClass) {
                    const args = withOrigin({ type: 'RestElement', argument: identifier('args', constructorOrigin) }, constructorOrigin);
                    params.push(args);
                    body.push(expressionStatement(call(withOrigin({ type: 'Super' }, constructorOrigin),
                        [withOrigin({ type: 'SpreadElement', argument: identifier('args', constructorOrigin) }, constructorOrigin)], constructorOrigin), constructorOrigin));
                }
                body.push(...instanceInitializers);
                constructor = withOrigin({
                    type: 'MethodDefinition', computed: false, static: false, kind: 'constructor',
                    key: identifier('constructor', constructorOrigin),
                    value: withOrigin({ type: 'FunctionExpression', id: null, params,
                        generator: false, async: false, expression: false, body: blockStatement(body, constructorOrigin) }, constructorOrigin),
                }, constructorOrigin);
                members.unshift(constructor);
            } else {
                const body = constructor.value.body.body;
                const superIndex = body.findIndex((statement) => statement.type === 'ExpressionStatement' &&
                    statement.expression && statement.expression.type === 'CallExpression' &&
                    statement.expression.callee && statement.expression.callee.type === 'Super');
                body.splice(superIndex + 1, 0, ...instanceInitializers);
            }
        }
        node.body.body = members;
        this.stripTypeFields(node.body);
        const classDecorators = node.decorators || [];
        this.stripTypeFields(node);
        for (const decorator of classDecorators) {
            if (node.id) decoratorCalls.push(expressionStatement(call(
                this.normalizeNode(decorator.expression), [identifier(node.id.name, decorator)], decorator), decorator));
        }
        return [node, ...staticInitializers, ...decoratorCalls];
    }

    jsxName(node) {
        if (!node) return identifier('undefined', node);
        if (node.type === 'JSXIdentifier') {
            return /^[a-z]/.test(node.name) ? literal(node.name, node) : identifier(node.name, node, false);
        }
        if (node.type === 'JSXMemberExpression') {
            return member(this.jsxName(node.object), this.jsxName(node.property), false, node);
        }
        if (node.type === 'JSXNamespacedName') {
            return literal(`${node.namespace.name}:${node.name.name}`, node);
        }
        return this.normalizeNode(node);
    }

    jsxFactory(origin) {
        if (this.compilerOptions.jsx === ts.JsxEmit.ReactJSX ||
            this.compilerOptions.jsx === ts.JsxEmit.ReactJSXDev) {
            const development = this.compilerOptions.jsx === ts.JsxEmit.ReactJSXDev;
            const importSource = this.compilerOptions.jsxImportSource || 'react';
            const runtimeModule = `${importSource}/${development ? 'jsx-dev-runtime' : 'jsx-runtime'}`;
            return member(requireCall(runtimeModule, origin, this.resolveModule(runtimeModule)),
                development ? 'jsxDEV' : 'jsx', false, origin);
        }
        const factory = this.compilerOptions.jsxFactory || 'React.createElement';
        const parts = factory.split('.');
        let result = identifier(parts.shift(), origin);
        for (const part of parts) result = member(result, part, false, origin);
        return result;
    }

    normalizeJsxElement(node) {
        const opening = node.openingElement;
        const tag = this.jsxName(opening.name);
        const properties = [];
        const spreads = [];
        for (const attribute of opening.attributes || []) {
            if (attribute.type === 'JSXSpreadAttribute') {
                spreads.push(this.normalizeNode(attribute.argument));
                continue;
            }
            const key = attribute.name.name || `${attribute.name.namespace.name}:${attribute.name.name.name}`;
            let value = attribute.value;
            if (!value) value = literal(true, attribute);
            else if (value.type === 'JSXExpressionContainer') value = this.normalizeNode(value.expression);
            else value = this.normalizeNode(value);
            properties.push(withOrigin({
                type: 'Property', kind: 'init', method: false, shorthand: false, computed: false,
                key: identifier(key, attribute), value,
            }, attribute));
        }
        let props = withOrigin({ type: 'ObjectExpression', properties }, opening);
        if (spreads.length) {
            props = call(member(identifier('Object', opening), 'assign', false, opening), [props, ...spreads], opening);
        }
        const children = [];
        for (const child of node.children || []) {
            if (child.type === 'JSXText') {
                const text = child.value.replace(/\s+/g, ' ').trim();
                if (text) children.push(literal(text, child));
            } else if (child.type === 'JSXExpressionContainer') {
                if (child.expression && child.expression.type !== 'JSXEmptyExpression') {
                    children.push(this.normalizeNode(child.expression));
                }
            } else {
                children.push(this.normalizeNode(child));
            }
        }
        return call(this.jsxFactory(node), [tag, props, ...children], node);
    }

    normalizeJsxFragment(node) {
        const fragmentFactory = this.compilerOptions.jsxFragmentFactory || 'React.Fragment';
        const parts = fragmentFactory.split('.');
        let fragment = identifier(parts.shift(), node);
        for (const part of parts) fragment = member(fragment, part, false, node);
        const children = [];
        for (const child of node.children || []) {
            if (child.type === 'JSXText') {
                const text = child.value.replace(/\s+/g, ' ').trim();
                if (text) children.push(literal(text, child));
            } else if (child.type === 'JSXExpressionContainer') {
                if (child.expression && child.expression.type !== 'JSXEmptyExpression') {
                    children.push(this.normalizeNode(child.expression));
                }
            } else children.push(this.normalizeNode(child));
        }
        return call(this.jsxFactory(node), [fragment,
            withOrigin({ type: 'ObjectExpression', properties: [] }, node), ...children], node);
    }
}

function createResolver(project, fileName) {
    const cache = ts.createModuleResolutionCache(
        path.dirname(fileName),
        ts.sys.useCaseSensitiveFileNames ? (name) => name : (name) => name.toLowerCase(),
        project.options,
    );
    const memo = new Map();
    return function resolveModule(specifier) {
        if (memo.has(specifier)) return memo.get(specifier);
        let result = null;
        try {
            const resolution = ts.resolveModuleName(specifier, fileName, project.options, ts.sys, cache).resolvedModule;
            if (resolution && resolution.resolvedFileName && !isDeclarationFile(resolution.resolvedFileName)) {
                result = normalizePath(resolution.resolvedFileName);
            }
        } catch (_) {
            result = null;
        }
        if (!result) {
            try {
                const fallback = searchModule(specifier, fileName)[0];
                if (fallback && fallback !== 'built-in' && !isDeclarationFile(fallback)) {
                    result = normalizePath(fallback);
                }
            } catch (_) {
                result = null;
            }
        }
        memo.set(specifier, result);
        return result;
    };
}

function moduleSpecifiers(sourceFile) {
    const specifiers = [];
    function visit(node) {
        if (ts.isImportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier)) {
            const clause = node.importClause;
            let runtime = !clause;
            if (clause && !clause.isTypeOnly) {
                runtime = Boolean(clause.name || (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) ||
                    (clause.namedBindings && ts.isNamedImports(clause.namedBindings) &&
                     clause.namedBindings.elements.some((element) => !element.isTypeOnly)));
            }
            if (runtime) specifiers.push(node.moduleSpecifier.text);
        } else if (ts.isExportDeclaration(node) && node.moduleSpecifier &&
            ts.isStringLiteralLike(node.moduleSpecifier)) {
            let runtime = !node.isTypeOnly;
            if (runtime && node.exportClause && ts.isNamedExports(node.exportClause)) {
                runtime = node.exportClause.elements.some((element) => !element.isTypeOnly);
            }
            if (runtime) specifiers.push(node.moduleSpecifier.text);
        } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference) &&
            node.moduleReference.expression && ts.isStringLiteralLike(node.moduleReference.expression)) {
            if (!node.isTypeOnly) specifiers.push(node.moduleReference.expression.text);
        } else if (ts.isCallExpression(node) && node.arguments.length && ts.isStringLiteralLike(node.arguments[0]) &&
            ((ts.isIdentifier(node.expression) && node.expression.text === 'require') ||
             node.expression.kind === ts.SyntaxKind.ImportKeyword)) {
            specifiers.push(node.arguments[0].text);
        }
        ts.forEachChild(node, visit);
    }
    visit(sourceFile);
    return specifiers;
}

function reachableProjectFiles(project) {
    const javascript = new Set(project.directoryInput ? collectJavaScriptFiles(project.inputPath) : []);
    const queue = project.entryFiles.map(normalizePath);
    const found = new Set();
    while (queue.length) {
        const fileName = queue.shift();
        if (found.has(fileName) || !isTypeScriptRuntimeFile(fileName)) continue;
        const sourceFile = project.program.getSourceFile(fileName);
        if (!sourceFile) continue;
        found.add(fileName);
        const resolveModule = createResolver(project, fileName);
        for (const specifier of moduleSpecifiers(sourceFile)) {
            const resolved = resolveModule(specifier);
            if (resolved && isTypeScriptRuntimeFile(resolved)) {
                if (!found.has(resolved)) queue.push(resolved);
            } else if (resolved && !isDeclarationFile(resolved) && RUNTIME_EXTENSIONS.has(path.extname(resolved))) {
                javascript.add(resolved);
            }
        }
    }
    return { typescript: [...found], javascript: [...javascript] };
}

function parseFile(project, fileName) {
    const sourceFile = project.program.getSourceFile(fileName);
    const sourceCode = sourceFile ? sourceFile.text : fs.readFileSync(fileName, 'utf8');
    const parsed = parseAndGenerateServices(sourceCode, {
        filePath: fileName,
        loc: true,
        range: true,
        comment: true,
        jsx: path.extname(fileName).toLowerCase() === '.tsx',
        programs: [project.program],
        preserveNodeMaps: true,
        errorOnUnknownASTType: false,
    });
    annotateSemantics(parsed.ast, parsed.services);
    const resolveModule = createResolver(project, fileName);
    const normalizer = new RuntimeNormalizer(fileName, sourceCode, project.options, resolveModule);
    const ast = normalizer.normalizeProgram(parsed.ast);
    return {
        filename: fileName,
        sourceCode,
        ast,
        info: {
            projectConfig: project.configPath,
            declarationMetadata: null,
            diagnostics: project.diagnostics,
            compiler: { path: require.resolve('typescript'), version: ts.version },
        },
    };
}

function parseStdin(sourceCode) {
    const fileName = 'stdin.ts';
    const parsed = parseAndGenerateServices(sourceCode, {
        filePath: fileName,
        loc: true,
        range: true,
        comment: true,
        jsx: true,
        projectService: { allowDefaultProject: ['stdin.ts'] },
        preserveNodeMaps: true,
    });
    annotateSemantics(parsed.ast, parsed.services);
    const project = {
        options: { jsx: ts.JsxEmit.React },
        configPath: null,
        diagnostics: [],
    };
    const normalizer = new RuntimeNormalizer(fileName, sourceCode, project.options, () => null);
    return {
        filename: 'stdin',
        sourceCode,
        ast: normalizer.normalizeProgram(parsed.ast),
        info: {
            projectConfig: null,
            declarationMetadata: null,
            diagnostics: [],
            compiler: { path: require.resolve('typescript'), version: ts.version },
        },
    };
}

function splitCsv(payload) {
    const separator = payload.indexOf('\n\n');
    if (separator < 0) throw new Error('Prepared AST emitter returned malformed CSV');
    return {
        nodes: payload.slice(0, separator).trimEnd().split('\n'),
        rels: payload.slice(separator + 2).trimEnd().split('\n'),
    };
}

function runCsvEmitter(payload, start) {
    const args = [
        path.join(__dirname, 'main.js'), '-', '--ast-json',
        '-n', String(start), '-o', '-', '--style', program.style,
        '--delimiter', program.delimiter,
    ];
    if (program.expression) args.push('-e');
    const result = childProcess.spawnSync(process.execPath, args, {
        input: JSON.stringify(payload),
        encoding: 'utf8',
        maxBuffer: 256 * 1024 * 1024,
    });
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.status !== 0) {
        throw new Error(`ESTree-to-CSV emission failed for ${payload.filename}: ${result.stderr || result.stdout}`);
    }
    return splitCsv(result.stdout);
}

function runJavaScriptEmitter(fileName, start) {
    const args = [
        path.join(__dirname, 'main.js'), fileName,
        '-n', String(start), '-o', '-', '--style', program.style,
        '--delimiter', program.delimiter,
    ];
    const result = childProcess.spawnSync(process.execPath, args, {
        encoding: 'utf8',
        maxBuffer: 256 * 1024 * 1024,
    });
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.status !== 0) {
        throw new Error(`JavaScript CSV emission failed for ${fileName}: ${result.stderr || result.stdout}`);
    }
    return splitCsv(result.stdout);
}

function maximumNodeId(nodeLines, delimiter) {
    let maximum = -1;
    const idColumn = program.style === 'c' ? 1 : 0;
    for (const line of nodeLines.slice(1)) {
        if (!line) continue;
        const value = Number(line.split(delimiter)[idColumn]);
        if (Number.isFinite(value)) maximum = Math.max(maximum, value);
    }
    return maximum;
}

function mergePayloads(payloads) {
    const delimiter = program.delimiter === 'comma' ? ',' : '\t';
    let start = Number.parseInt(program.start, 10);
    if (!Number.isFinite(start)) start = program.style === 'c' ? 1 : 0;
    let nodeHeader = null;
    let relHeader = null;
    const nodes = [];
    const rels = [];
    for (const payload of payloads) {
        const emitted = payload.javascript ?
            runJavaScriptEmitter(payload.javascript, start) : runCsvEmitter(payload, start);
        nodeHeader = nodeHeader || emitted.nodes[0];
        relHeader = relHeader || emitted.rels[0];
        nodes.push(...emitted.nodes.slice(1).filter(Boolean));
        rels.push(...emitted.rels.slice(1).filter(Boolean));
        start = maximumNodeId(emitted.nodes, delimiter) + 1;
    }
    return `${nodeHeader || ''}\n${nodes.join('\n')}\n\n${relHeader || ''}\n${rels.join('\n')}\n`;
}

function writeOutput(csv) {
    if (program.output === '-' || (program.input === '-' && program.output === undefined)) {
        process.stdout.write(csv);
        return;
    }
    const outputDirectory = normalizePath(program.output || '.');
    fs.mkdirSync(outputDirectory, { recursive: true });
    const parts = splitCsv(csv);
    fs.writeFileSync(path.join(outputDirectory, 'nodes.csv'), parts.nodes.join('\n') + '\n');
    fs.writeFileSync(path.join(outputDirectory, program.style === 'php' ? 'rels.csv' : 'edges.csv'),
        parts.rels.join('\n') + '\n');
}

function main() {
    let payloads;
    if (program.input === '-') {
        payloads = [parseStdin(fs.readFileSync(0, 'utf8'))];
    } else {
        if (!fs.existsSync(program.input)) throw new Error(`Input does not exist: ${program.input}`);
        const projects = loadProjects(program.input);
        const seenTypeScript = new Set();
        const seenJavaScript = new Set();
        const typescriptPayloads = [];
        const javascriptPayloads = [];
        for (const project of projects) {
            const files = reachableProjectFiles(project);
            let projectDiagnosticsAttached = false;
            for (const fileName of files.typescript) {
                if (seenTypeScript.has(fileName)) continue;
                seenTypeScript.add(fileName);
                const payload = parseFile(project, fileName);
                if (projectDiagnosticsAttached) payload.info.diagnostics = [];
                else projectDiagnosticsAttached = true;
                typescriptPayloads.push(payload);
            }
            for (const javascript of files.javascript) {
                if (seenJavaScript.has(javascript)) continue;
                seenJavaScript.add(javascript);
                javascriptPayloads.push({ javascript });
            }
        }
        if (!typescriptPayloads.length) throw new Error(`No runtime TypeScript files found for ${program.input}`);
        payloads = [
            ...typescriptPayloads,
            ...javascriptPayloads,
        ];
    }
    writeOutput(mergePayloads(payloads));
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
}
