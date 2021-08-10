'use strict'

const joi = require('joi');
const nconf = require('nconf');

function validate(config) {

    const schema = joi.object({
        gatewayIP: joi.string().min(1).default('192.168.4.1'),
        localNetwork: joi.string().min(1).default('192.168.4.0/24'),
        networkConfig: joi.object({
            local: joi.boolean().default(false),
            gateway: joi.boolean().default(false),
            wifi: joi.boolean().default(false),
            wbridge: joi.boolean().default(false),
            vpn: joi.boolean().default(false),
            wan: joi.string().min(1).default('eth0'),
            wlan: joi.string().min(1).default('wlan0'),
            lan: joi.string().min(1).default('eth1')
        }).default(),
        transparent: joi.bool().default(false),
    });
    return joi.attempt(config, schema, {allowUnknown: true, stripUnknown: true});
} // end validate

// Resolved config object
function Config(info) {
    // Read environment variables
    nconf.env('__');

    let config = {}
    if (info) {
        config = info;
    } else {
        config.localNetwork = nconf.get('LOCAL_NETWORK');
        config.transparent = nconf.get('TRANSPARENT');
    }

    const validatedConfig = validate(config);
	
    Object.assign(this, validatedConfig);
}

module.exports = Config;
