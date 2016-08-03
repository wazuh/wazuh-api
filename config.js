
var config = {};


// Port
// TCP Port used by the API.
config.port = "55000";

// Security
// Use HTTP protocol over TLS/SSL. Values: yes, no.
config.https = "yes";
// Use HTTP authentication. Values: yes, no.
config.basic_auth = "yes";
//In case the API run behind a proxy server, turn to "yes" this feature. Values: yes, no.
config.BehindProxyServer = "no";
// Cross-origin resource sharing. Values: yes, no.
config.cors = "yes";

// Paths
config.ossec_path = "/var/ossec";
config.log_path = "/var/ossec/logs/api.log";
config.api_path = __dirname;

// Logs
// Values for API log: disabled, info, warning, error, debug (each level includes the previous level).
config.logs = "debug";
config.logs_tag = "WazuhAPI";


module.exports = config;
