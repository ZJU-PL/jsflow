function __importDefault(mod) {
  return mod && mod.__esModule ? mod : { default: mod };
}

function __extends(derived, base) {
  for (var key in base) derived[key] = base[key];
  derived.prototype = Object.create(base && base.prototype);
  derived.prototype.constructor = derived;
}

function __createBinding(target, source, key, alias) {
  target[alias || key] = source[key];
}

function __setModuleDefault(target, value) {
  target.default = value;
}

function __importStar(mod) {
  if (mod && mod.__esModule) return mod;
  var result = {};
  if (mod) {
    for (var key in mod) {
      if (key !== "default") result[key] = mod[key];
    }
  }
  result.default = mod;
  return result;
}

function __exportStar(mod, exportsObject) {
  for (var key in mod) {
    if (key !== "default") exportsObject[key] = mod[key];
  }
}

function __decorate(decorators, target, key, descriptor) {
  var result = descriptor || target;
  for (var index = decorators.length - 1; index >= 0; index--) {
    var decorator = decorators[index];
    result = decorator(target, key, result) || result;
  }
  if (key && target && target[key]) {
    var OPGen_TAINTED_VAR_request = "";
    target[key](OPGen_TAINTED_VAR_request, OPGen_TAINTED_VAR_request);
  }
  return result;
}

function __metadata(key, value) {
  return function(target) { return target; };
}

function __param(index, decorator) {
  return function(target, key) { decorator(target, key, index); };
}

function __awaiter(thisArg, argumentsObject, promiseConstructor, generator) {
  var iterator = generator.apply(thisArg, argumentsObject || []);
  var step = iterator.next();
  return step.value;
}

function __generator(thisArg, body) {
  var iterator = body.call(thisArg, {
    label: 0,
    sent: function() { return undefined; },
    trys: [],
    ops: []
  });
  return iterator || { next: function() { return { done: true }; } };
}

function __await(value) {
  this.v = value;
}

function __asyncGenerator(thisArg, argumentsObject, generator) {
  return generator.apply(thisArg, argumentsObject || []);
}

function __asyncDelegator(iterator) {
  return iterator;
}

function __asyncValues(value) {
  if (value && value[Symbol.asyncIterator]) return value[Symbol.asyncIterator]();
  return __values(value);
}

function __assign(target) {
  for (var index = 1; index < arguments.length; index++) {
    var source = arguments[index];
    for (var key in source) target[key] = source[key];
  }
  return target;
}

function __rest(source, excluded) {
  var target = {};
  for (var key in source) {
    if (excluded.indexOf(key) < 0) target[key] = source[key];
  }
  return target;
}

function __values(value) {
  if (value && value[Symbol.iterator]) return value[Symbol.iterator]();
  var index = 0;
  return {
    next: function() {
      if (!value || index >= value.length) return { done: true };
      return { done: false, value: value[index++] };
    }
  };
}

function __read(value, count) {
  var result = [];
  var iterator = __values(value);
  var step;
  while ((count === undefined || result.length < count) && !(step = iterator.next()).done) {
    result.push(step.value);
  }
  return result;
}

function __spreadArray(target, source) {
  for (var index = 0; index < source.length; index++) target.push(source[index]);
  return target;
}

function __spread() {
  var result = [];
  for (var index = 0; index < arguments.length; index++) {
    result = __spreadArray(result, __read(arguments[index]));
  }
  return result;
}

function __spreadArrays() {
  var result = [];
  for (var index = 0; index < arguments.length; index++) {
    result = __spreadArray(result, arguments[index]);
  }
  return result;
}

function __classPrivateFieldGet(receiver, state, kind, accessor) {
  if (kind === "a") return accessor.call(receiver);
  if (kind === "m") return accessor;
  if (state && state.get) return state.get(receiver);
  return receiver[state];
}

function __classPrivateFieldSet(receiver, state, value, kind, accessor) {
  if (kind === "a") accessor.call(receiver, value);
  else if (state && state.set) state.set(receiver, value);
  else receiver[state] = value;
  return value;
}

function __classPrivateFieldIn(state, receiver) {
  return state && state.has ? state.has(receiver) : state in receiver;
}

function __runInitializers(thisArg, initializers, value) {
  var current = value;
  for (var index = 0; index < initializers.length; index++) {
    current = initializers[index].call(thisArg, current);
  }
  return current;
}

function __esDecorate(target, descriptor, decorators, context, initializers, extraInitializers) {
  var value = descriptor && descriptor.value ? descriptor.value : target;
  for (var index = decorators.length - 1; index >= 0; index--) {
    value = decorators[index](value, context) || value;
  }
  if (descriptor) descriptor.value = value;
  if (context && context.addInitializer) context.addInitializer(function() {});
  return value;
}

function __propKey(value) {
  return typeof value === "symbol" ? value : String(value);
}

function __setFunctionName(func, name, prefix) {
  func.name = prefix ? prefix + " " + name : name;
  return func;
}

function __makeTemplateObject(cooked, raw) {
  cooked.raw = raw;
  return cooked;
}

function __addDisposableResource(environment, value, async) {
  if (value) environment.stack.push({ value: value, async: async });
  return value;
}

function __disposeResources(environment) {
  while (environment.stack.length) {
    var resource = environment.stack.pop();
    var disposer = resource.value.dispose || resource.value.close;
    if (disposer) disposer.call(resource.value);
  }
}

function __rewriteRelativeImportExtension(pathValue) {
  return pathValue;
}

module.exports = {
  __addDisposableResource: __addDisposableResource,
  __assign: __assign,
  __asyncGenerator: __asyncGenerator,
  __asyncDelegator: __asyncDelegator,
  __asyncValues: __asyncValues,
  __await: __await,
  __awaiter: __awaiter,
  __classPrivateFieldGet: __classPrivateFieldGet,
  __classPrivateFieldIn: __classPrivateFieldIn,
  __classPrivateFieldSet: __classPrivateFieldSet,
  __createBinding: __createBinding,
  __decorate: __decorate,
  __disposeResources: __disposeResources,
  __esDecorate: __esDecorate,
  __exportStar: __exportStar,
  __extends: __extends,
  __generator: __generator,
  __importDefault: __importDefault,
  __importStar: __importStar,
  __makeTemplateObject: __makeTemplateObject,
  __metadata: __metadata,
  __param: __param,
  __propKey: __propKey,
  __read: __read,
  __rest: __rest,
  __runInitializers: __runInitializers,
  __rewriteRelativeImportExtension: __rewriteRelativeImportExtension,
  __setFunctionName: __setFunctionName,
  __setModuleDefault: __setModuleDefault,
  __spreadArray: __spreadArray,
  __spread: __spread,
  __spreadArrays: __spreadArrays,
  __values: __values
};
