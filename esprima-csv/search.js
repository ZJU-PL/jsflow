#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const builtInModules = require('module').builtinModules;
const ansicolor = require('ansicolor').nice;
const bundledTypeScriptPath = require.resolve('typescript');
let ts = require(bundledTypeScriptPath);
let activeTypeScriptPath = bundledTypeScriptPath;

const packageJsonCache = new Map();
const workspaceDirectoryCache = new Map();
const typescriptConfigCache = new Map();
const moduleResolutionCache = new Map();

const args = process.argv.slice(2);
const noBuiltinPackages = args.includes('--no-builtin-packages');
const filteredArgs = args.filter((arg) => arg !== '--no-builtin-packages');

function findTypeScriptConfig(fromPath) {
    let searchDirectory = fromPath;
    if (fs.existsSync(fromPath) && fs.statSync(fromPath).isFile()) {
        searchDirectory = path.dirname(fromPath);
    }
    const cacheKey = `${activeTypeScriptPath}:${path.resolve(searchDirectory)}`;
    if (typescriptConfigCache.has(cacheKey)) return typescriptConfigCache.get(cacheKey);
    const configPath = ts.findConfigFile(searchDirectory, ts.sys.fileExists, 'tsconfig.json');
    if (!configPath) return {};
    const loaded = ts.readConfigFile(configPath, ts.sys.readFile);
    if (loaded.error) return {};
    const options = ts.parseJsonConfigFileContent(loaded.config, ts.sys, path.dirname(configPath)).options;
    typescriptConfigCache.set(cacheKey, options);
    return options;
}

function activateProjectTypeScript(fromPath) {
    let resolvedPath = bundledTypeScriptPath;
    try {
        const searchPath = fs.existsSync(fromPath) && fs.statSync(fromPath).isFile() ? path.dirname(fromPath) : fromPath;
        resolvedPath = require.resolve('typescript', { paths: [path.resolve(searchPath)] });
    } catch (_) {
        resolvedPath = bundledTypeScriptPath;
    }
    if (resolvedPath !== activeTypeScriptPath) {
        ts = require(resolvedPath);
        activeTypeScriptPath = resolvedPath;
    }
}

function resolveTypeScriptModule(moduleName, requiredBy) {
    activateProjectTypeScript(requiredBy);
    let containingFile = requiredBy;
    if (!fs.existsSync(containingFile) || fs.statSync(containingFile).isDirectory()) {
        containingFile = path.join(containingFile, '__probejs__.ts');
    }
    const compilerOptions = Object.assign({
        allowJs: true,
        resolveJsonModule: true,
        moduleResolution: ts.ModuleResolutionKind.Node10,
    }, findTypeScriptConfig(containingFile));
    const resolution = ts.resolveModuleName(moduleName, containingFile, compilerOptions, ts.sys);
    const resolved = resolution && resolution.resolvedModule;
    return resolved && resolved.resolvedFileName ? resolved.resolvedFileName : null;
}

function readPackageJson(packagePath) {
    const jsonPath = path.join(packagePath, 'package.json');
    if (packageJsonCache.has(jsonPath)) return packageJsonCache.get(jsonPath);
    try {
        const value = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
        packageJsonCache.set(jsonPath, value);
        return value;
    } catch (_) {
        packageJsonCache.set(jsonPath, null);
        return null;
    }
}

function findWorkspaceRoot(fromPath) {
    let current = fs.existsSync(fromPath) && fs.statSync(fromPath).isFile() ? path.dirname(fromPath) : fromPath;
    current = path.resolve(current);
    while (current !== path.dirname(current)) {
        const packageJson = readPackageJson(current);
        if ((packageJson && packageJson.workspaces) || fs.existsSync(path.join(current, 'pnpm-workspace.yaml'))) {
            return current;
        }
        current = path.dirname(current);
    }
    return null;
}

function listWorkspacePackageDirectories(workspaceRoot) {
    if (workspaceDirectoryCache.has(workspaceRoot)) return workspaceDirectoryCache.get(workspaceRoot);
    const result = [workspaceRoot];
    const pending = [workspaceRoot];
    while (pending.length) {
        const current = pending.pop();
        let entries;
        try {
            entries = fs.readdirSync(current, { withFileTypes: true });
        } catch (_) {
            continue;
        }
        for (const entry of entries) {
            if (!entry.isDirectory() || ['node_modules', '.git', 'dist', 'build', 'coverage'].includes(entry.name)) continue;
            const child = path.join(current, entry.name);
            if (fs.existsSync(path.join(child, 'package.json'))) result.push(child);
            pending.push(child);
        }
    }
    workspaceDirectoryCache.set(workspaceRoot, result);
    return result;
}

function splitPackageRequest(moduleName) {
    const parts = moduleName.split('/');
    const packageName = moduleName.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
    return { packageName, subpath: parts.slice(moduleName.startsWith('@') ? 2 : 1).join('/') };
}

function selectExportTarget(value) {
    if (typeof value === 'string') return value;
    if (!value || typeof value !== 'object') return null;
    return selectExportTarget(value.require) || selectExportTarget(value.node) ||
        selectExportTarget(value['node-addons']) || selectExportTarget(value.development) ||
        selectExportTarget(value.production) || selectExportTarget(value.import) ||
        selectExportTarget(value.default);
}

function resolvePackageExport(packageDirectory, packageJson, subpath = '') {
    const exportsField = packageJson && packageJson.exports;
    if (!exportsField) return null;
    const key = subpath ? `./${subpath}` : '.';
    let target = typeof exportsField === 'string' ? exportsField : exportsField[key];
    if (!target && typeof exportsField === 'object') {
        for (const pattern of Object.keys(exportsField)) {
            if (!pattern.includes('*')) continue;
            const [prefix, suffix] = pattern.split('*');
            if (key.startsWith(prefix) && key.endsWith(suffix || '')) {
                const wildcard = key.slice(prefix.length, suffix ? -suffix.length : undefined);
                const selected = selectExportTarget(exportsField[pattern]);
                if (selected) target = selected.replace('*', wildcard);
                break;
            }
        }
    }
    const selected = selectExportTarget(target);
    return selected ? resolveFile(path.resolve(packageDirectory, selected.replace(/^\.\//, ''))) : null;
}

function resolvePackageImport(moduleName, requiredBy) {
    if (!moduleName.startsWith('#')) return null;
    let current = fs.existsSync(requiredBy) && fs.statSync(requiredBy).isFile() ? path.dirname(requiredBy) : requiredBy;
    current = path.resolve(current);
    while (current !== path.dirname(current)) {
        const packageJson = readPackageJson(current);
        const target = packageJson && packageJson.imports && selectExportTarget(packageJson.imports[moduleName]);
        if (target) return resolveFile(path.resolve(current, target.replace(/^\.\//, '')));
        current = path.dirname(current);
    }
    return null;
}

function resolveWorkspaceModule(moduleName, requiredBy) {
    const workspaceRoot = findWorkspaceRoot(requiredBy);
    if (!workspaceRoot) return null;
    const request = splitPackageRequest(moduleName);
    for (const packageDirectory of listWorkspacePackageDirectories(workspaceRoot)) {
        const packageJson = readPackageJson(packageDirectory);
        if (!packageJson || packageJson.name !== request.packageName) continue;
        const exported = resolvePackageExport(packageDirectory, packageJson, request.subpath);
        if (exported) return exported;
        if (request.subpath) {
            const subpath = resolveFile(path.join(packageDirectory, request.subpath));
            if (subpath) return subpath;
        }
        return searchMain(packageDirectory);
    }
    return null;
}

function resolveFile(candidate) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
    for (const extension of ['.js', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.ets']) {
        if (fs.existsSync(candidate + extension) && fs.statSync(candidate + extension).isFile()) return candidate + extension;
    }
    for (const extension of ['.js', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.ets']) {
        const indexFile = path.join(candidate, 'index' + extension);
        if (fs.existsSync(indexFile) && fs.statSync(indexFile).isFile()) return indexFile;
    }
    return null;
}

function searchModule(moduleName, requiredBy, disableBuiltinPackages = false) {
    const resolutionCacheKey = `${moduleName}\0${path.resolve(requiredBy)}\0${disableBuiltinPackages}`;
    if (moduleResolutionCache.has(resolutionCacheKey)) return moduleResolutionCache.get(resolutionCacheKey);
    const remember = (result) => {
        moduleResolutionCache.set(resolutionCacheKey, result);
        return result;
    };
    var selfBuiltPackages = ['yargs', 'execa', 'express', 'fastify', '@nestjs/common', '@nestjs/core', 'send', 'async', 'mz/child_process', 'denodeify','commander', 'platform-command', 'grunt', 'pm', 'boom', 'async', 'tslib'];
    selfBuiltPackages = selfBuiltPackages.concat(['mongodb', 'monk']);
    if (builtInModules.includes(moduleName) || selfBuiltPackages.indexOf(moduleName) >= 0) {
        if (disableBuiltinPackages) {
            return remember(['built-in', 'built-in']);
        }
        // console.error(`${moduleName.blue.bright} is a built-in module.`);
        let searchPaths = new Set();
        let currentSearchPath = __dirname;
        // search JavaScript-modeled built-in modules
        while (currentSearchPath != path.resolve(currentSearchPath, '..')) {
            searchPaths.add(path.resolve(currentSearchPath, 'builtin_packages'));
            currentSearchPath = path.resolve(currentSearchPath, '..');
        }
        for (let p of searchPaths) {
            const filePath = path.resolve(p, moduleName + '.js');
            if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
                console.error(`Package ${moduleName} found at ${filePath}.`.white.inverse);
                return remember([filePath, p]);
            }
        }
        // unmodeled built-in modules
        return remember(['built-in', 'built-in']);
    }
    const resolvedPackageImport = resolvePackageImport(moduleName, requiredBy);
    if (resolvedPackageImport) {
        console.error(`Package import ${moduleName} found at ${resolvedPackageImport}.`.white.inverse);
        return remember([resolvedPackageImport, path.dirname(resolvedPackageImport)]);
    }
    const resolvedTypeScriptModule = resolveTypeScriptModule(moduleName, requiredBy);
    if (resolvedTypeScriptModule) {
        console.error(`Package ${moduleName} found at ${resolvedTypeScriptModule}.`.white.inverse);
        return remember([resolvedTypeScriptModule, path.dirname(resolvedTypeScriptModule)]);
    }
    const resolvedWorkspaceModule = resolveWorkspaceModule(moduleName, requiredBy);
    if (resolvedWorkspaceModule) {
        console.error(`Workspace package ${moduleName} found at ${resolvedWorkspaceModule}.`.white.inverse);
        return remember([resolvedWorkspaceModule, path.dirname(resolvedWorkspaceModule)]);
    }
    let searchPaths = new Set();
    if (fs.existsSync(requiredBy) && fs.statSync(requiredBy).isFile()) {
        requiredBy = path.resolve(requiredBy, '..');
    }
    searchPaths.add(requiredBy); // TODO: logic is not the same as Node
    let currentSearchPath = requiredBy;
    while (currentSearchPath != path.resolve(currentSearchPath, '..')) { // this probably will only work under Linux/Unix
        searchPaths.add(path.resolve(currentSearchPath, 'node_modules'));
        currentSearchPath = path.resolve(currentSearchPath, '..');
    }
    searchPaths.add('/node_modules');
    searchPaths.add(path.resolve(os.homedir(), '.node_modules'));
    searchPaths.add(path.resolve(os.homedir(), '.node_libraries'));
    searchPaths.add(path.resolve(os.homedir(), 'packagecrawler'));
    console.error(`Searching ${moduleName.blue.bright} in ${Array.from(searchPaths).toString().green}`);
    let found = false;
    let mainPath, modulePath;
    for (let p of searchPaths) {
        let currentPath = path.resolve(p, moduleName);
        // search file
        // console.error(currentPath);
        if (fs.existsSync(currentPath) && fs.statSync(currentPath).isFile()) {
            console.error(`Package ${moduleName} found at ${currentPath}`.white.inverse);
            found = true;
            modulePath = currentPath;
            mainPath = currentPath;
            break;
        }
        if (!found) {
            // search directory
            currentPath = path.resolve(p, moduleName);
            // console.error(currentPath);
            if (fs.existsSync(currentPath) && fs.statSync(currentPath).isDirectory()) {
                mainPath = searchMain(currentPath);
                if (mainPath != null) {
                    console.error(`Package ${moduleName} found at ${mainPath}.`.white.inverse);
                    found = true;
                    modulePath = currentPath;
                    break;
                }
            }
        }
        if (!found && !/\.[cm]?[jt]sx?$/i.test(moduleName)){
            for (const extension of ['.js', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.ets']) {
                const candidatePath = currentPath + extension;
                if (fs.existsSync(candidatePath) && fs.statSync(candidatePath).isFile()) {
                    console.error(`Package ${moduleName} found at ${candidatePath}`.white.inverse);
                    found = true;
                    modulePath = candidatePath;
                    mainPath = candidatePath;
                    break;
                }
            }
        }
    }
    if (!found) {
        console.error(`Error: required package ${moduleName} not found.`.lightRed.inverse);
    }
    return remember([mainPath, modulePath]);
}

function searchMain(packagePath) {
    // check if package.json exists
    let jsonPath = path.resolve(packagePath, 'package.json');
    let main;
    if (fs.existsSync(jsonPath) && fs.statSync(jsonPath).isFile()) {
        try {
            const packageJson = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
            const exportedPath = resolvePackageExport(packagePath, packageJson);
            if (exportedPath) return exportedPath;
            main = packageJson.source || packageJson.main || packageJson.module;
        } catch (e) {
            console.error(`Error: package.json (${jsonPath}) does not include main field.`.lightRed.inverse);
        }
    }
    main = main || 'index';
    let mainPath = path.resolve(packagePath, String(main).replace(/^\.\//, ''));
    if (fs.existsSync(mainPath) && fs.statSync(mainPath).isDirectory()) {
        mainPath = path.resolve(mainPath, 'index');
    }
    if (fs.existsSync(mainPath) && fs.statSync(mainPath).isFile()) {
        return mainPath;
    }
    for (const extension of ['.js', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.ets']) {
        const candidatePath = mainPath.endsWith(extension) ? mainPath : mainPath + extension;
        if (fs.existsSync(candidatePath) && fs.statSync(candidatePath).isFile()) {
            return candidatePath;
        }
    }
    return null;
}

module.exports.searchModule = searchModule;
module.exports.searchMain = searchMain;

if (require.main === module) {
    if (filteredArgs.length != 2) {
        console.error('Wrong arguments, usage: search.js [--no-builtin-packages] <module name> <search path>');
    } else {
        var mainPath, modulePath;
        [mainPath, modulePath] = searchModule(filteredArgs[0], filteredArgs[1], noBuiltinPackages);
        if (mainPath && modulePath){
            console.log(mainPath);
            console.log(modulePath);
        } else {
            console.log();
        }
    }
}
