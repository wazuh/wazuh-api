
var config = {};

config.ossec_path = "/var/ossec";
config.port = "55000";
config.logs = "info";  // Values: disabled, info, warning, error, debug (each level includes the previous level).

module.exports = config;
