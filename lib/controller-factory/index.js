'use strict';

let Router = require('koa-router');
let path = require('path');
let appRoot = require('app-root-path');

class Controller {
  constructor(routerBinding) {
    this._router = null;
    this._routerBinding = routerBinding;
  }

  bindRouter(router) {
    this._router = router;
    this._routerBinding(router);
  }

  getMiddleware() {
    return this._router.middleware();
  }
}

class ControllerFactory {
  static load(pathToAction) {
    return require(path.join(appRoot + '/controllers', pathToAction));
  }

  static loadByAcceptType(pathToAction) {
    return async function() {
      let ext = this.accepts(['json', 'html']) === 'html' ? 'html' : 'json';
      let action = ControllerFactory.load(pathToAction + '.' + ext);

      await action();
    };
  }

  static create(routerBinding) {
    let controllerMiddleware = function(app) {
      let controller = new Controller(routerBinding);
      controller.bindRouter(new Router());
      app.use(controller.getMiddleware());
    };

    controllerMiddleware.Controller = Controller;
    controllerMiddleware.Factory = ControllerFactory;

    return controllerMiddleware;
  }
}


module.exports = ControllerFactory;
