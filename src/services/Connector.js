const core = require('gls-core-service');
const BasicConnector = core.services.Connector;
const env = require('../data/env');
const Auth = require('../controllers/Auth');

class Connector extends BasicConnector {
    constructor() {
        super();

        this._auth = new Auth({ connector: this });
    }

    async start() {
        const auth = this._auth;

        await super.start({
            serverRoutes: {
                'auth.authorize': auth.authorize.bind(auth),
                'auth.generateSecret': auth.generateSecret.bind(auth),
            },
            requiredClients: {
                frontend: env.GLS_FRONTEND_GATE_CONNECT,
            },
        });
    }
}

module.exports = Connector;
