// Описание переменных окружения смотри в Readme.
const env = process.env;

module.exports = {
    GLS_FRONTEND_GATE_HOST: env.GLS_FRONTEND_GATE_HOST || '0.0.0.0',
    GLS_FRONTEND_GATE_PORT: env.GLS_FRONTEND_GATE_PORT || 8080,
    GLS_FRONTEND_GATE_TIMEOUT_FOR_CLIENT: env.GLS_FRONTEND_GATE_TIMEOUT_FOR_CLIENT || 60000,
};
