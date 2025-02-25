const ipRangeCheck = require('ip-range-check');

module.exports = {
    ALLOWED_IPS: [
        '127.0.0.1',
        '::1',
        // Rangos CIDR
        '10.0.0.0/24',     // Ejemplo de red interna
        // Añadir más IPs o rangos CIDR permitidos
    ],
    IP_WHITELIST_ENABLED: true
};