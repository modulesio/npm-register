'use strict'

const htpasswd = require('htpasswd-auth')
const uuid = require('node-uuid')
const config = require('../config')
const cofs = require('co-fs')
const base32 = require('base32')

function * getCreds () {
  return yield JSON.parse((yield config.storage.get('auth_tokens')) || '{}')
}

function * createAuthToken (username) {
  let creds = yield getCreds()
  let token = uuid.v4()
  creds[token] = {
    username,
    timestamp: new Date()
  }
  yield config.storage.put('auth_tokens', creds, {
    'Content-Type': 'application/json'
  })
  return token
}

function * authenticate (user) {
  let creds = (yield config.storage.get('htpasswd')) || ''
  const credentials = JSON.parse(yield cofs.readFile(config.auth.credentialsPath, 'utf8'));
  const configUser = credentials[base32.decode(user.name)];
  if (configUser && configUser.password === user.password) {
    return user.name + ':' + user.password;
  } else {
    return false;
  }
}

function * findByToken (token) {
  const split = token.split(':');
  if (split.length === 2) {
    const [user, password] = split;

    const credentials = JSON.parse(yield cofs.readFile(config.auth.credentialsPath, 'utf8'));
    const configUser = credentials[base32.decode(user)];
    if (configUser && configUser.password === password) {
      return user;
    } else {
      return undefined;
    }
  } else {
    return undefined;
  }
}

exports.authenticate = authenticate
exports.findByToken = findByToken
