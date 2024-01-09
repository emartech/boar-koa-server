'use strict';

let fs = require('fs');
let cors = require('@koa/cors');
let methodOverride = require('koa-methodoverride');
let bodyparser = require('koa-bodyparser');
let requestId = require('koa-requestid');
let ssl = require('koa-ssl');
let SecurityMiddlewareFactory = require('../lib/security-middleware-factory');


class App {
  constructor(koaApp) {
    this.koaApp = koaApp;
  }

  addCorsSupportMiddleware({ allowOrigin, allowMethods } = {
    allowOrigin: '*',
    allowMethods: 'GET,HEAD,PUT,POST,DELETE,PATCH'
  }) {
    let origin = '*';
    if (allowOrigin instanceof RegExp) {
      origin = function(ctx) {
        const incoming = ctx.get('Origin');
        if (incoming.match(allowOrigin)) {
          return incoming;
        }
        // eslint-disable-next-line security/detect-unsafe-regex
        if (incoming.match(/\/localhost(:\d+)?$/)) {
          return incoming;
        }
      };
    }
    this.addMiddleware(cors({
      origin,
      allowMethods
    }));
  }

  loadControllers(path) {
    fs.readdirSync(path).forEach(function(file) {
      let filePath = path + '/' + file + '/index.js';
      if (!fs.existsSync(filePath)) {
        return;
      }
      require(filePath)(this.koaApp);
    }.bind(this));
  }

  addMiddleware(middleware) {
    this.koaApp.use(middleware);
  }

  addMethodOverrideMiddleware(fieldName) {
    this.addMiddleware(methodOverride(fieldName));
  }

  addBodyParseMiddleware(options) {
    this.addMiddleware(bodyparser(options));
  }

  addRequestIdMiddleware(options) {
    options = options || { expose: 'x-request-id', header: 'x-request-id', query: 'x-request-id' };
    this.addMiddleware(requestId(options));
  }

  addSecurityMiddlewares(options) {
    new SecurityMiddlewareFactory(options)
      .getMiddlewares()
      .forEach(this.addMiddleware, this);
  }

  addEnforceSSLMiddleware(options) {
    this.addMiddleware(ssl(options));
  }
}

module.exports = App;
