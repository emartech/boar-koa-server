# Boar Koa Server

## Example usage for app

put these lines in your server.js
``` javascript
  const Koa = require('koa');
  const path = require('path');
  const koaApp = module.exports = new Koa();
  const config = require('./config');
  const App = require('@emartech/boar-koa-server').app;

  const app = new App(koaApp);
  app.loadControllers(path.join(config.root, 'controllers'));

  if (!module.parent) { app.listen(config.port); }
```

## Add middleware for your app
``` javascript
  const cors = require('koa-cors');
  const app = new App(koaApp);
  app.addMiddleware(cors());
```

## Build-in Middlewares

### Cors Support ([@koa/cors](https://www.npmjs.com/package/@koa/cors))

``` javascript
  app.addCorsSupportMiddleware();
```

Allowed settings :
``` javascript
  app.addCorsSupportMiddleware({
    allowOrigin: '*', // `Access-Control-Allow-Origin`, * or a regex to filter allowed origins (for instance /emarsys.(com|net)$/)
    allowMethods: 'GET,HEAD,PUT,POST,DELETE,PATCH', // `Access-Control-Allow-Methods`
  });
```

**⚠️ WARNING ⚠️** : 
Not specifying an allowed origin made the middleware always return an `Access-Control-Allow-Origin` header with the value of the origin from the request. This behavior completely disables one of the most crucial elements of browsers - the Same Origin Policy (SOP), this could cause a very serious security threat to the users of this middleware.

Since version `2.0.0`, the package is based `@koa/cors@5.0.0` which
[disables this behavior](https://www.npmjs.com/package/@koa/cors/v/5.0.0#breaking-change-between-50-and-40).
It is **highly recommended** to specify a list of allowed origins.

### Method Override ([koa-methodoverwrite](https://github.com/koa-modules/methodoverride))

``` javascript
  app.addMethodOverrideMiddleware();
```

### Body Parse ([koa-bodyparser](https://github.com/koajs/body-parser))

| Param | Type  | Description |
| ----- | ----- | ----------- |
| __options__ | `Object` | [More info.](https://github.com/koajs/bodyparser#options) |

``` javascript
  app.addBodyParseMiddleware(options);
```

### Request Id ([koa-requestid](https://github.com/seegno/koa-requestid))

| Param | Type  | Description |
| ----- | ----- | ----------- |
| __options__ | `Object` | _optional_ |
| ↳header | `String` | The name of the header to read the id on the request, `false` to disable. |
| ↳query  | `String` | The name of the header to read the id on the query string, `false` to disable. |
| ↳expose | `String` | The name of the header to expose the id on the response, `false` to disable. |

``` javascript
  app.addRequestIdmiddleware(options);
```

### Enforce SSL ([koa-ssl](https://github.com/jclem/koa-ssl))

| Param | Type  | Description |
| ----- | ----- | ----------- |
| __options__ | `Object` | [More info.](https://github.com/jclem/koa-ssl#use) |

``` javascript
  app.addEnforceSSLMiddleware();
```

If your application is running behind reverse proxy (like Heroku) you should set the trustProxy configuration option to *true* in order to process the x-forwarded-proto header.

``` javascript
  const app = new App(koaApp);
  app.addEnforceSSLMiddleware({ trustProxy: true });
```

__Note__: if you use this middleware EnforceSSL middleware should be the first you add.

### Security
Provides middlewares for setting up various security related HTTP headers.

| Param | Type  | Description |
| ----- | ----- | ----------- |
| __options__ | `Object` |  |
| ↳csp | `Object` | [More info.](https://github.com/helmetjs/csp) Learn more: [CSP quick reference](http://content-security-policy.com/) |
| ↳hsts | `Object` | [More info.](https://github.com/helmetjs/hsts) Learn more: [OWASP HSTS page](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security) |
| ↳useXssFilter | `Boolean` | If `true`, [x-xss-protection](https://github.com/helmetjs/x-xss-protection) middleware will be included. Default: `true` |
| ↳useNoSniff | `Boolean` |  If `true`, [dont-sniff-mimetype](https://github.com/helmetjs/dont-sniff-mimetype) middleware will be included. Default: `true` |
| ↳referrerPolicy| `Boolean,Object` | If`{ policy: 'same-origin'}`, [referrer-policy](https://github.com/helmetjs/referrer-policy) middleware will be included. Default `false` |

``` javascript
  app.addSecurityMiddlewares(options);
```

#### Default configuration
``` javascript
  {
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
      includeSubDomains: true,
      preload: false
    },
    useXssFilter: true,
    useNoSniff: true,
    referrerPolicy: false
  }
```


## Libraries

### ControllerFactory
``` javascript
  var ControllerFactory = require('@emartech/boar-koa-server').lib.controllerFactory;

  module.exports = ControllerFactory.create(function(router) {
    router.get('/', ControllerFactory.load('main/actions/get'));
    router.get('/healthcheck', ControllerFactory.load('main/actions/healthcheck/get'));
    router.get('/list', ControllerFactory.loadByAcceptType('main/actions/list/get'));
  });
```

