const random = require('randomstring');
const crypto = require('crypto');
const fetch = require('node-fetch');
const core = require('gls-core-service');
const env = require('../data/env');
const { JsonRpc } = require('cyberwayjs');
const Signature = require('eosjs-ecc/lib/signature');
const { convertLegacyPublicKey } = require('cyberwayjs/dist/eosjs-numeric');
const Basic = core.controllers.Basic;
const Logger = core.utils.Logger;
const RPC = new JsonRpc(env.GLS_CYBERWAY_HTTP_URL, { fetch });

class Auth extends Basic {
    constructor({ connector }) {
        super({ connector });
        this._secretMap = new Map();
    }
    async authorize({ user, sign, secret, channelId }) {
        const storedSecret = this._secretMap.get(channelId);
        secret = Buffer.from(secret);

        if (!storedSecret.equals(secret)) {
            throw { code: 1103, message: 'Secret verification failed - access denied' };
        }
        const transactionObject = {
            transaction: { serializedTransaction: secret, signatures: [sign] },
        };

        const publicKeyFromBlockchain = convertLegacyPublicKey(
            await this._getPublicKeyFromBc({ username: user })
        );

        const publicKeyVerified = this._verifyKey({
            ...transactionObject,
            publicKey: publicKeyFromBlockchain,
        });

        if (!publicKeyVerified) {
            throw { code: 1103, message: 'Secret verification failed - access denied' };
        }
        this._secretMap.delete(channelId);

        return {
            user,
            roles: [],
        };
    }

    _verifyKey({ transaction: { serializedTransaction, signatures }, publicKey }) {
        try {
            const sgn = Signature.from(signatures[0]);
            return sgn.verify(serializedTransaction, publicKey);
        } catch (error) {
            Logger.error(error);
            return false;
        }
    }
    async _getPublicKeyFromBc({ username } = {}) {
        const accountData = await RPC.get_account(username);

        if (!accountData) {
            throw {
                code: 11011,
                message: 'Such an account does not exist',
            };
        }

        return accountData.permissions[0].required_auth.keys[0].key;
    }

    async generateSecret({ channelId }) {
        const salt = random.generate();
        const hash = crypto.createHash('sha1');
        const secret = hash
            .update(Buffer.from(salt + channelId))
            .digest()
            .toString('hex');

        const serializedSecret = Buffer.from(secret);
        this._secretMap.set(channelId, serializedSecret);

        return { secret };
    }
}

module.exports = Auth;
