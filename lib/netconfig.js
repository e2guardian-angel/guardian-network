'use strict';
const iptabler = require('iptabler');
const netconfig = require('network-config');
const shelljs = require('shelljs');
const Config = require('./config');
const joi = require('joi');
const Netmask = require('new-netmask').Netmask;
const dnsmasq = require('dnsmasq');
const fs = require('fs');
const systemctl = require('systemctl');

function NetworkConfigurator(networkConfig) {
    this.allRules = [];
    this.allNatRules = [];
    this.interfaces = shelljs.ls('/sys/class/net');
    this.firewallRules = JSON.parse(fs.readFileSync(`${__dirname}/json/firewall.json`));
    this.config = new Config(networkConfig);
    this.dhcpServers = {};
}

/*
 * Firewall rules
 */
NetworkConfigurator.prototype.getAllRules = async function() {
    // First get a list of all existing rules
    const netConfig = this;
    const allRulesCmd = iptabler({
        sudo: true,
        S: ''
    });
    const allNatRulesCmd = iptabler({
        sudo: true,
        table: 'nat',
        S: ''
    });
    allRulesCmd._args.pop();
    allNatRulesCmd._args.pop();
    await allRulesCmd.exec(function(err, stdout) {
        if (err) {
            throw err;
        }
        netConfig.allRules = stdout.split('\n');
    });
    await allNatRulesCmd.exec(function(err, stdout) {
        if (err) {
            throw err;
        }
        netConfig.allNatRules = stdout.split('\n');
    });
};

NetworkConfigurator.prototype.applyRule = async function(rule) {
    const iptablesRule = iptabler(rule);
    let cmd = iptablesRule._args.slice();
    cmd.shift();
    let ruleStr = cmd.join(' ');

    let ruleExists = false;
    if (ruleStr.indexOf('-t nat') >= 0) {
        // This is a nat rule
        ruleStr = ruleStr.replace('-t nat', '').trim();
        ruleExists = this.allNatRules.indexOf(ruleStr) >= 0;
    } else {
        ruleExists = this.allRules.indexOf(ruleStr) >= 0;
    }

    // Apply rule only if it doesn't already exist
    if (!ruleExists) {
        console.log('applying rule');
        await iptabler(rule).exec(function(stdout, err) {
            if(err) {
                throw err;
            }
        });
    } else {
        console.log('Rule already applied');
    }
};

NetworkConfigurator.prototype.applyRules = async function(rules) {
    for (let i = 0; i < rules.length; i++) {
        await this.applyRule(rules[i]);
    }
};

NetworkConfigurator.prototype.flushChain = async function(chain, nat) {
    let rule = {
        sudo: true,
        flush: chain
    };
    if (nat) {
        rule.table = 'nat';
    }
    await iptabler(rule).exec(err => {
        if (err) {
            console.error(`Error flushing chain ${chain} :: ${err.message}`)
        }
    });
};

NetworkConfigurator.prototype.flushAllChains = async function() {
    await this.flushChain('GUARDIAN-OUTPUT', true);
    await this.flushChain('GUARDIAN-PREROUTING', true);
    await this.flushChain('GUARDIAN-FORWARD');
    await this.flushChain('GUARDIAN-POSTROUTING', true);
}

/*
 * Network configuration
 */

NetworkConfigurator.prototype.configureInterface = async function(conf) {

    const schema = joi.object({
        interface: joi.string().min(1).required(),
        network: joi.object({
            network: joi.string().ip().default('192.168.4.0'),
            netmask: joi.string().ip().default('255.255.255.0')
        }).required(),
        type: joi.string().valid('ethernet', 'wireless').default('ethernet'),
        transparent: joi.boolean().default(false),
        dhcpServer: joi.boolean().default(false),
        domain: joi.string().min(1).default('guardian-angel.local'),
        leaseLength: joi.string().min(1).default('24h'),
        gateway: joi.boolean().default(false),
        wan: joi.string().min(1).optional()
    });

    const validated = joi.attempt(conf, schema);
    const i = validated.interface;

    if (this.interfaces.indexOf(i) < 0) {
        throw new Error(`Can't configure non-existent interface: ${i}`);
    } else {
        // Configure interface
        const block = new Netmask(validated.network.network, validated.network.netmask);
        validated.network.ip = block.first; // Static IP must be first in the block
        let beginIpParts = block.first.split('.');
        beginIpParts[3] = `${parseInt(beginIpParts[3]) + 1}`;
        let beginIp = beginIpParts.join('.');
        let endIp = block.last;

        await netconfig.configure(i, validated.network, function(err) {
            if (err) {
                throw err;
            }
        });

        if (!validated.network.dhcp && validated.dhcpServer) {
            if (
                !validated.network.ip ||
                !validated.network.netmask ||
                !validated.network.network
            ) {
                throw new Error(`Missing one of: [ip, netmask, network] from interface definition '${i}'`);
            }

            // Configure DHCP server
            const dnsmasqConf = Object.assign({
                'interface': i,
                'listen-address': '127.0.0.1',
                'domain': validated.domain,
                'dhcp-range': `${beginIp},${endIp},${validated.network.netmask},${validated.leaseLength}`
            }, dnsmasq.conf('/etc/dnsmasq.conf'));
            const dhcpServer = dnsmasq(config);
            dhcpServer.start(() => {
                console.info(`dnsmasq started as dhcp server on interface ${i}`);
            });
            this.dhcpServers[i] = dhcpServer;

            if (validated.gateway) {
                if (!validated.wan) {
                    throw new Error(`Interface ${i} configured as gateway but WAN not specified`);
                }

                // Enable forwarding
                if (!fs.existsSync('/etc/sysctl.d/routed-ap.conf')) {
                    fs.writeFileSync('/etc/sysctl.d/routed-ap.conf', 'net.ipv4.ip_forward=1');
                    await systemctl.restart('procps');
                }

                // Apply forwarding rules
                const forwardRuleStr = JSON.stringify(this.firewallRules.forward, null, 2);
                forwardRuleStr.replace('LAN', i);
                forwardRuleStr.replace('WAN');
                const forwardRules = JSON.parse(forwardRuleStr);
                await this.applyRules(forwardRules);
            }

            if (validated.transparent) {
                // Apply transparent proxy rules
                const transparentRuleStr = JSON.stringify(this.firewallRules.gatewayTransparent, null, 2);
                transparentRuleStr.replace('LAN', i);
                transparentRuleStr.replace('GATEWAY_IP', validated.ip);
                await this.applyRules(transparentRuleStr);
            }

            // TODO: start hostapd for wireless
        } else {
            // Stop dnsmasq
            if(this.dhcpServers[i]) {
                this.dhcpServers[i].stop(() => {
                    console.info(`Stopped dnsmasq as dhcp server on interface ${i}`);
                });
            }

            // Disable forward

            // TODO: stop hostapd for wireless
        }
    }
};

NetworkConfigurator.prototype.configureInterfaces = async function() {
    const nConf = this.config.networkConfig;
    await this.flushAllChains();

    // Disable forwarding by default
    fs.unlinkSync('/etc/sysctl.d/routed-ap.conf');
    await systemctl.restart('procps');

    // TODO: kill all dnsmasq servers

    // TODO: configure all interfaces

};

module.exports = NetworkConfigurator;
