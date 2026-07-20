function decoratorFactory() {
  return function(target, key, descriptor) { return descriptor || target; };
}

function Injectable() { return decoratorFactory(); }
function Controller() { return decoratorFactory(); }
function Module() { return decoratorFactory(); }
function Get() { return decoratorFactory(); }
function Post() { return decoratorFactory(); }
function Put() { return decoratorFactory(); }
function Delete() { return decoratorFactory(); }
function Patch() { return decoratorFactory(); }
function Body() { return decoratorFactory(); }
function Param() { return decoratorFactory(); }
function Query() { return decoratorFactory(); }
function Req() { return decoratorFactory(); }
function Res() { return decoratorFactory(); }

module.exports = {
  Injectable, Controller, Module, Get, Post, Put, Delete, Patch,
  Body, Param, Query, Req, Res
};
