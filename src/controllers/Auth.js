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

        if (!storedSecret) {
            Logger.error('Auth error -- stored secret does not exist');

            throw {
                code: 1102,
                message:
                    "There is no secret stored for this channelId. Probably, client's already authorized",
            };
        }

        if (!storedSecret.equals(secretBuffer)) {
            throw { code: 1103, message: 'Secret verification failed - access denied' };
        }

        const { displayName, accountName } = await this._resolveNames(user);

        const publicKeys = await this._getPublicKeyFromBc({ username: accountName });

        const publicKeysPermission = this._verifyKeys({
            secretBuffer,
            sign,
            publicKeys,
        });

        if (!publicKeysPermission) {
            Logger.error(
                'Public key is not valid',
                JSON.stringify(
                    { publicKeysPermission, publicKeys, displayName, accountName },
                    null,
                    2
                )
            );
            throw { code: 1103, message: 'Public key verification failed - access denied' };
        }
        this._secretMap.delete(channelId);

        return {
            user: accountName,
            displayName,
            roles: [],
            permission: publicKeysPermission,
        };
    }

    async _resolveNames(user) {
        const names = { displayName: user, accountName: user };
        if (user.includes('@')) {
            try {
                const resolved = await RPC.fetch('/v1/chain/resolve_names', [user]);
                names.accountName = resolved[0].resolved_username;
                names.displayName = user.split('@')[0];
            } catch (error) {
                Logger.error('Error resolve account name -- ', error);
            }
        }
        return names;
    }

    _verifyParamsOrThrow({ user, sign, secret, channelId }) {
        if (!user || !sign || !secret || !channelId) {
            throw { code: 1102, message: 'Service failed - not all params are set' };
        }
    }

    _verifyKeys({ secretBuffer, sign, publicKeys }) {
        let signature;
        try {
            signature = Signature.from(sign);
        } catch (error) {
            throw {
                code: 1102,
                message: 'Sign is not a valid signature',
            };
        }
        for (const { publicKey, permission } of publicKeys) {
            try {
                const verified = signature.verify(secretBuffer, publicKey);
                if (verified) {
                    return permission;
                }
            } catch (error) {
                Logger.error('Key cannot be verified --', error.stack);
            }
        }

        return false;
    }
    async _getPublicKeyFromBc({ username } = {}) {
        try {
            const accountData = await RPC.get_account(username);

            return accountData.permissions.map(permission => {
                return {
                    publicKey: convertLegacyPublicKey(permission.required_auth.keys[0].key),
                    permission: permission.perm_name,
                };
            });
        } catch (error) {
            throw {
                code: 11011,
                message: 'Cannot get such account from BC',
                error,
            };
        }
    }

    async generateSecret({ channelId }) {
        const existedSecret = this._secretMap.get(channelId);

        if (existedSecret) {
            return {
                secret: existedSecret.toString(),
            };
        }

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
