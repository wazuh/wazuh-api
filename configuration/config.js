
var config = {};

// Basic configuration

// Path
config.ossec_path = "/var/ossec";
// The host to bind the API to.
config.host = "0.0.0.0";
// TCP Port used by the API.
config.port = "55000";
// Use HTTP protocol over TLS/SSL. Values: yes, no.
config.https = "no";
// Use HTTP authentication. Values: yes, no.
config.basic_auth = "yes";
//In case the API run behind a proxy server, turn to "yes" this feature. Values: yes, no.
config.BehindProxyServer = "no";

// HTTPS Certificates
config.https_key = "configuration/ssl/server.key"
config.https_cert = "configuration/ssl/server.crt"
config.https_use_ca = "no"
config.https_ca = "configuration/ssl/ca.crt"

// Advanced configuration

// Values for API log: disabled, info, warning, error, debug (each level includes the previous level).
config.logs = "info";
// Cross-origin resource sharing. Values: yes, no.
config.cors = "yes";
// Cache (time in milliseconds)
config.cache_enabled = "yes";
config.cache_debug = "no";
config.cache_time = "750";
// Log path
config.log_path = config.ossec_path + "/logs/api.log";
// Python
config.python = [
    // Default installation
    {
        bin: "python",
        lib: ""
    },
    // Python 3
    {
        bin: "python3",
        lib: ""
    },
    // Package 'python27' for CentOS 6
    {
        bin: "/opt/rh/python27/root/usr/bin/python",
        lib: "/opt/rh/python27/root/usr/lib64"
    }
];
// Shared library path
config.ld_library_path = config.ossec_path + "/api/framework/lib"

module.exports = config;
