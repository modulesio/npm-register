'use strict'

const user = require('../lib/user')
const config = require('../config')
const cofs = require('co-fs')
const base32 = require('base32')

function * doAuth (ctx, next) {
  if (ctx.headers.authorization) {
    let token = ctx.headers.authorization.split(' ')[1]
    ctx.username = yield user.findByToken(token)
  }
  if (!ctx.username) ctx.throw(401)
  const credentials = JSON.parse(yield cofs.readFile(config.auth.credentialsPath, 'utf8'));
  const configUser = credentials[base32.decode(ctx.username)];
  const match = ctx.path.match(/^\/@((?:(?!%2f).)+)%2f(.+)$/);
  if (match) {
    const packageUser = match[1];
    const packageName = match[2];

    if (packageUser === config.auth.scope) {
      const configModule = configUser.modules[packageName];

      if (configModule) {
        if (ctx.method === 'GET' && configModule.read) {
          yield next
        } else if (ctx.method !== 'GET' && configModule.write) {
          yield next
        } else {
          ctx.throw(401)
        }
      } else {
        ctx.throw(401)
      }
    } else {
      ctx.throw(401);
    }
  } else {
    ctx.throw(401);
  }
}

module.exports = {
  read: function * (next) {
    yield doAuth(this, next)
  },
  write: function * (next) {
    yield doAuth(this, next)
  },
  always: function * (next) {
    yield doAuth(this, next)
  }
}
