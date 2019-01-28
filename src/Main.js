const core = require('gls-core-service');
const stats = core.utils.statsClient;
const InnerGate = core.services.Connector;
const BasicMain = core.services.BasicMain;
const env = require('./data/env');
const Connector = require('./services/Connector');

class Main extends BasicMain {
    constructor() {
        super(stats, env);
        this.addNested(new Connector());
    }
}

module.exports = Main;
