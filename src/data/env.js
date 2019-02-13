const env = process.env;

if (!env.CMN_CYBERWAY_HTTP_URL) {
    throw 'CMN_CYBERWAY_HTTP_URL env variable is required';
}

module.exports = {
    GLS_CONNECTOR_HOST: env.GLS_CONNECTOR_HOST || '127.0.0.0',
    GLS_CONNECTOR_PORT: env.GLS_CONNECTOR_PORT || 3000,
    CMN_CYBERWAY_HTTP_URL: env.CMN_CYBERWAY_HTTP_URL,
};
