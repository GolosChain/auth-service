const core = require('gls-core-service');
const Basic = core.controllers.Basic;

class Auth extends Basic {
    async authorize({ user, sign, secret, ...data }) {}

    async generateSecret() {}
}

module.exports = Auth;
