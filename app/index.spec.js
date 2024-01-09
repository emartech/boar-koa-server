'use strict';

const Koa = require('koa');
const request = require('supertest');
const App = require('./');
const { expect } = require('chai');

describe('Application building', () => {
  describe('CORS', () => {
    describe('default allowed origins', () => {
      let koa;
      let server;

      before(() => {
        koa = new Koa();
        const app = new App(koa);
        app.addCorsSupportMiddleware();
        koa.use(function(ctx) {
          ctx.body = { foo: 'bar' };
        });
        server = koa.listen();
      });

      after(() => {
        server.close();
      });

      it('should set `Access-Control-Allow-Origin` to `*` when request Origin header missing', () => {
        return request(server)
          .get('/')
          .expect({ foo: 'bar' })
          .expect('access-control-allow-origin', '*')
          .expect(200);
      });

      it('should set `Access-Control-Allow-Origin` to `*`', () => {
        return request(server)
          .get('/')
          .set('Origin', 'http://koajs.com')
          .expect('Access-Control-Allow-Origin', '*')
          .expect({ foo: 'bar' })
          .expect(200);
      });

      it('should 204 on Preflight Request', () => {
        return request(server)
          .options('/')
          .set('Origin', 'http://koajs.com')
          .set('Access-Control-Request-Method', 'PUT')
          .expect('Access-Control-Allow-Origin', '*')
          .expect('Access-Control-Allow-Methods', 'GET,HEAD,PUT,POST,DELETE,PATCH')
          .expect(204);
      });

      it('should not Preflight Request if request missing Access-Control-Request-Method', () => {
        return request(server)
          .options('/')
          .set('Origin', 'http://koajs.com')
          .expect(200);
      });

      it('should always set `Vary` to Origin', () => {
        return request(server)
          .get('/')
          .set('Origin', 'http://koajs.com')
          .expect('Vary', 'Origin')
          .expect({ foo: 'bar' })
          .expect(200);
      });
    });

    describe('specific settings', () => {
      let koa;
      let server;

      before(() => {
        koa = new Koa();
        const app = new App(koa);
        app.addCorsSupportMiddleware({
          allowOrigin: /emarsys\.(com|net)$/,
          allowMethods: 'GET,POST'
        });
        koa.use(function(ctx) {
          ctx.body = { foo: 'bar' };
        });
        server = koa.listen();
      });

      after(() => {
        server.close();
      });

      it('should not set `Access-Control-Allow-Origin` when request Origin header missing', async () => {
        const response = await request(server)
          .get('/')
          .expect({ foo: 'bar' })
          .expect(200);
        expect(response.headers['access-control-allow-origin']).to.be.undefined;
      });

      it('should not set `Access-Control-Allow-Origin` when request Origin does not match', async () => {
        const response = await request(server)
          .get('/')
          .set('Origin', 'http://koajs.com')
          .expect({ foo: 'bar' })
          .expect(200);
        expect(response.headers['access-control-allow-origin']).to.be.undefined;
      });

      it('should set `Access-Control-Allow-Origin` when request Origin match', () => {
        return request(server)
          .get('/')
          .set('Origin', 'https://anyserver.emarsys.com')
          .expect({ foo: 'bar' })
          .expect('access-control-allow-origin', 'https://anyserver.emarsys.com')
          .expect(200);
      });

      it('should 204 on Preflight Request', () => {
        return request(server)
          .options('/')
          .set('Origin', 'https://anyserver.emarsys.com')
          .set('Access-Control-Request-Method', 'GET,POST')
          .expect('Access-Control-Allow-Origin', 'https://anyserver.emarsys.com')
          .expect(204);
      });

      it('should 204 on Preflight Request for local development', () => {
        return request(server)
          .options('/')
          .set('Origin', 'http://localhost:4000')
          .set('Access-Control-Request-Method', 'GET,POST')
          .expect('Access-Control-Allow-Origin', 'http://localhost:4000')
          .expect(204);
      });

      it('should not Preflight Request if request Origin does not match', async () => {
        const response = await request(server)
          .options('/')
          .set('Origin', 'http://koajs.com')
          .expect(200);
        expect(response.headers['access-control-allow-origin']).to.be.undefined;
      });
    });
  });
});
