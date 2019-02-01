const env = process.env;

module.exports = {
    GLS_CONNECTOR_HOST: env.GLS_CONNECTOR_HOST || '127.0.0.0',
    GLS_CONNECTOR_PORT: env.GLS_CONNECTOR_PORT || 3000,
};
