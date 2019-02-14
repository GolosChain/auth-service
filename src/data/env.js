const env = process.env;

if (!env.GLS_CYBERWAY_HTTP_URL) {
    throw 'GLS_CYBERWAY_HTTP_URL env variable is required';
}

module.exports = {
    GLS_CONNECTOR_HOST: env.GLS_CONNECTOR_HOST || '127.0.0.0',
    GLS_CONNECTOR_PORT: env.GLS_CONNECTOR_PORT || 3000,
    GLS_CYBERWAY_HTTP_URL: env.GLS_CYBERWAY_HTTP_URL,
};
