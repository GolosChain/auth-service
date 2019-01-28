const core = require('gls-core-service');
const Basic = core.controllers.Basic;
const random = require('randomstring');
const crypto = require('crypto');
const golos = require('golos-js');

class Auth extends Basic {
    constructor({ connector }) {
        super({ connector });
        this._secretMap = new Map();
    }
    async authorize({ user, sign, secret, channelId, ...data }) {
        if (this._secretMap.get(channelId) !== secret) {
            throw { code: 1103, message: 'Secret verification failed - access denied' };
        }
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

    async generateSecret({ channelId }) {
        const salt = random.generate();
        const hash = crypto.createHash('sha1');
        const secret = hash
            .update(Buffer.from(salt + channelId))
            .digest()
            .toString('hex');
        this._secretMap.set(channelId, secret);
        return secret;
    }
}

module.exports = Auth;
