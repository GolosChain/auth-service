const core = require('gls-core-service');
const Basic = core.controllers.Basic;
const random = require('randomstring');
const golos = require('golos-js');

class Auth extends Basic {
    async authorize({ user, sign, secret, ...data }) {}

    async generateSecret() {}
}

module.exports = Auth;
