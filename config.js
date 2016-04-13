
var config = {};

// Port
config.port = "55000";

// Security
config.https = "yes"; // Values: yes, no
config.basic_auth = "yes"; // Values: yes, no
config.BehindProxyServer = "no";

// Paths
config.ossec_path = "/var/ossec";
config.log_path = "/var/ossec/logs/api.log";
config.api_path = __dirname;

// Logs
config.logs = "info";  // Values: disabled, info, warning, error, debug (each level includes the previous level).
config.logs_tag = "WazuhAPI";

module.exports = config;
