var NestFactory = {
  create: function() {
    return {
      listen: function() {},
      init: function() {},
      use: function(callback) { OPGen_markTaintCall(callback); },
      useGlobalPipes: function() {},
      useGlobalGuards: function() {}
    };
  }
};

module.exports = { NestFactory: NestFactory };
