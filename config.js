
var config = {};

// Port
config.port = "55000";

// Security
config.https = "yes"; // Values: yes, no
config.basic_auth = "yes"; // Values: yes, no
config.AccessControlAllowOrigin = ["*"];
config.AccessControlAllowHeaders = ["kbn-version"];
config.BehindProxyServer = "no";

// Paths
config.ossec_path = "/var/ossec";
config.api_path = __dirname;

// Logs
config.logs = "debug";  // Values: disabled, info, warning, error, debug (each level includes the previous level).
config.logs_tag = "WazuhAPI";

module.exports = config;
