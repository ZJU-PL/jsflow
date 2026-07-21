function makeReply() {
  return {
    send: function(value) { return value; },
    code: function() { return this; },
    header: function() { return this; }
  };
}

function invoke(handler) {
  if (typeof handler === 'function') {
    OPGen_markTaintCall(handler);
  }
}

function fastify() {
  var app = {};
  app.get = function(path, options, handler) { invoke(options); invoke(handler); return app; };
  app.post = function(path, options, handler) { invoke(options); invoke(handler); return app; };
  app.put = function(path, options, handler) { invoke(options); invoke(handler); return app; };
  app.delete = function(path, options, handler) { invoke(options); invoke(handler); return app; };
  app.route = function(options) { invoke(options && options.handler); return app; };
  app.register = function(plugin) { invoke(plugin); return app; };
  app.listen = function() { return app; };
  return app;
}

module.exports = fastify;
