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

    // TODO Refactor in next iteration
    async authorize(params) {
        return await this._authorize(params);
    }

    async _authorize({ user, sign, secret, channelId }) {
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

        try {
            const publicKeys = await this._getPublicKeyFromBc(accountName);

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
        } catch (originalError) {
            if (!user.includes('@')) {
                try {
                    return await this._authorize({
                        user: `${user}@golos`,
                        sign,
                        secret,
                        channelId,
                    });
                } catch (error) {
                    // Если пользователь user@golos вообще не найден, то выдаем первичную ошибку.
                    if (
                        error.name === 'username_query_exception' &&
                        error.details.length &&
                        error.details[0].message.includes(' not found in scope ')
                    ) {
                        throw originalError;
                    }

                    throw error;
                }
            }

            throw originalError;
        }
    }

    async _resolveNames(user) {
        if (user.includes('@')) {
            try {
                const resolved = await RPC.fetch('/v1/chain/resolve_names', [user]);

                return {
                    accountName: resolved[0].resolved_username,
                    displayName: user.split('@')[0],
                };
            } catch (error) {
                if (error && error.json && error.json.error) {
                    throw error.json.error;
                } else {
                    throw error;
                }
            }
        } else {
            return { displayName: user, accountName: user };
        }
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

    async _getPublicKeyFromBc(userId) {
        try {
            const accountData = await RPC.get_account(userId);

            return accountData.permissions.map(permission => ({
                publicKey: convertLegacyPublicKey(permission.required_auth.keys[0].key),
                permission: permission.perm_name,
            }));
        } catch (error) {
            if (error && error.json && error.json.error) {
                if (error.json.error.name !== 'chaindb_midx_find_exception') {
                    Logger.error('getPublicKeyFromBc failed:', error.json.error);
                }
            } else {
                Logger.error('getPublicKeyFromBc failed:', JSON.stringify(error, null, 4));
            }

            throw { code: 11011, message: 'Cannot get such account from BC' };
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
