const random = require('randomstring');
const crypto = require('crypto');
const fetch = require('node-fetch');
const core = require('gls-core-service');
const { JsonRpc } = require('cyberwayjs');
const Signature = require('eosjs-ecc/lib/signature');
const { convertLegacyPublicKey } = require('cyberwayjs/dist/eosjs-numeric');
const env = require('../data/env');
const Basic = core.controllers.Basic;
const Logger = core.utils.Logger;
const RPC = new JsonRpc(env.GLS_CYBERWAY_HTTP_URL, { fetch });

class Auth extends Basic {
    constructor({ connector }) {
        super({ connector });
        this._secretMap = new Map();
    }
    async authorize({ user, sign, secret, channelId }) {
        this._verifyParamsOrThrow({ user, sign, secret, channelId });

        const storedSecret = this._secretMap.get(channelId);
        const secretBuffer = Buffer.from(secret);

        if (!storedSecret.equals(secretBuffer)) {
            throw { code: 1103, message: 'Secret verification failed - access denied' };
        }

        const publicKeys = await this._getPublicKeyFromBc({ username: user });

        const publicKeysVerified = this._verifyKeys({
            secretBuffer,
            sign,
            publicKeys,
        });

        if (!publicKeysVerified) {
            throw { code: 1103, message: 'Secret verification failed - access denied' };
        }
        this._secretMap.delete(channelId);

        return {
            user,
            roles: [],
        };
    }

    _verifyParamsOrThrow({ user, sign, secret, channelId }) {
        if (!user || !sign || !secret || !channelId) {
            throw { code: 1102, message: 'Service failed - not all params are set' };
        }
    }

    _verifyKeys({ secretBuffer, sign, publicKeys }) {
        let verified = false;
        for (const publicKey of publicKeys) {
            try {
                const sgn = Signature.from(sign);
                sgn.verify(secretBuffer, publicKey);
                verified = true;
            } catch (error) {
                Logger.error(error);
            } finally {
                if (verified) {
                    return true;
                }
            }
        }

        return false;
    }
    async _getPublicKeyFromBc({ username } = {}) {
        const accountData = await RPC.get_account(username);

        if (!accountData) {
            throw {
                code: 11011,
                message: 'Such an account does not exist',
            };
        }

        return accountData.permissions.map(permission =>
            convertLegacyPublicKey(permission.required_auth.keys[0].key)
        );
    }

    async generateSecret({ channelId }) {
        const seed = random.generate();
        const hash = crypto.createHash('sha1');
        const secret = hash
            .update(Buffer.from(seed + channelId))
            .digest()
            .toString('hex');

        const serializedSecret = Buffer.from(secret);
        this._secretMap.set(channelId, serializedSecret);

        return { secret };
    }
}

module.exports = Auth;
