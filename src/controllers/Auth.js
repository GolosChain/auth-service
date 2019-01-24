const core = require('gls-core-service');
const Basic = core.controllers.Basic;
const random = require('randomstring');
const golos = require('golos-js');

class Auth extends Basic {
    async authorize({ user, sign, secret, ...data }) {
        const signObject = this._makeUserFakeTransactionObject(user, sign, secret);

        try {
            await golos.api.verifyAuthorityAsync(signObject);
        } catch (error) {
            throw { code: 1103, message: 'Blockchain verification failed - access denied' };
        }

        return {
            ...data,
            sign,
            user,
            roles: [],
        };
    }

    _makeUserFakeTransactionObject(user, sign, secret) {
        return {
            ref_block_num: 3367,
            ref_block_prefix: 879276768,
            expiration: '2018-07-06T14:52:24',
            operations: [
                [
                    'vote',
                    {
                        voter: user,
                        author: 'test',
                        permlink: secret,
                        weight: 1,
                    },
                ],
            ],
            extensions: [],
            signatures: [sign],
        };
    }

    async generateSecret() {
        return random.generate();
    }
}

module.exports = Auth;
