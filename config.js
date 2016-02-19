
var config = {};

// Port
config.port = "55000";

// Paths
config.ossec_path = "/var/ossec";
config.api_path = __dirname;

// Logs
config.logs = "info";  // Values: disabled, info, warning, error, debug (each level includes the previous level).
config.logs_tag = "WazuhAPI";

module.exports = config;
