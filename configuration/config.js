
var config = {};

// Basic configuration

// Path
config.ossec_path = "/var/ossec";
// TCP Port used by the API.
config.port = "55000";
// Use HTTP protocol over TLS/SSL. Values: yes, no.
config.https = "no";
// Use HTTP authentication. Values: yes, no.
config.basic_auth = "yes";
//In case the API run behind a proxy server, turn to "yes" this feature. Values: yes, no.
config.BehindProxyServer = "no";


// Advanced configuration

// Values for API log: disabled, info, warning, error, debug (each level includes the previous level).
config.logs = "info";
// Cross-origin resource sharing. Values: yes, no.
config.cors = "yes";
// Cache (time in milliseconds)
config.cache_enabled = "yes"
config.cache_debug = "no"
config.cache_time = "750"
// Log path
config.log_path = config.ossec_path + "/logs/api.log";


module.exports = config;
