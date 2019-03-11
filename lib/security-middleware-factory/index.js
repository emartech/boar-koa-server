'use strict';

const deepExtend = require('deep-extend');
const helmet = require('koa-helmet');

class SecurityMiddlewareFactory {

  constructor(options) {
    this._config = deepExtend({}, this.defaultConfig, options);
  }

  get defaultConfig() {
    return {
      csp: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'"],
          frameAncestors: ["'self'"],
          reportUri: 'about:blank'
        },
        reportOnly: true
      },
      hsts: {
        maxAge: 30,
        includeSubdomains: true,
        preload: false
      },
      useXssFilter: true,
      useNoSniff: true,
      referrerPolicy: false
    };
  }

  getCspMiddleware() {
    return helmet.contentSecurityPolicy(this._config.csp);
  }

  getHstsMiddleware() {
    return helmet.hsts(this._config.hsts);
  }

  getXssFilterMiddleware() {
    return helmet.xssFilter();
  }

  getNoSniffMiddleware() {
    return helmet.noSniff();
  }

  getReferrerPolicyMiddleware() {
    return helmet.referrerPolicy(this._config.referrerPolicy);
  }

  getMiddlewares() {
    let middlewares = [
      this.getCspMiddleware(),
      this.getHstsMiddleware()
    ];

    if (this._config.useXssFilter) {
      middlewares.push(this.getXssFilterMiddleware());
    }

    if (this._config.useNoSniff) {
      middlewares.push(this.getNoSniffMiddleware());
    }

    if (this._config.referrerPolicy) {
      middlewares.push(this.getReferrerPolicyMiddleware());
    }

    return middlewares;
  }
}

module.exports = SecurityMiddlewareFactory;
