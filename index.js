'use strict';

module.exports = {

  app: require('./app'),

  lib: {
    controllerFactory: require('./lib/controller-factory'),
    securityMiddlewareFactory: require('./lib/security-middleware-factory')
  }

};
