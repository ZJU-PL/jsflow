exports.argv = __opgTaintedWildcard;
exports.argv._ = __opgTaintedWildcard;
// exports.argv._.shift = function() {return __opgTaintedWildcard;};
// exports.argv._.pop = function() {return __opgTaintedWildcard;};

function command(name, description, builder, handler) {
  if (typeof builder === 'function') builder(module.exports);
  if (typeof handler === 'function') OPGen_markTaintCall(handler);
  return module.exports;
}

function option() { return module.exports; }
function demandCommand() { return module.exports; }
function help() { return module.exports; }

module.exports.command = command;
module.exports.option = option;
module.exports.demandCommand = demandCommand;
module.exports.help = help;
