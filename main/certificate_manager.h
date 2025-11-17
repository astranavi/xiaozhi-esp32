#ifndef CERTIFICATE_MANAGER_H
#define CERTIFICATE_MANAGER_H

#include <string>

// Configuration constants
#define MTLS_SECRET "43a2e807246197060f5a1085bca2e5fde58ed0e9c3bc603e46ca2bc6921ddd9d"
#define CERT_REQUEST_PATH "/cert/sign"
#define CERT_NVS_NAMESPACE "mtls"

// Certificate storage paths in certs partition
#define CERT_FILE_CA "/certs/ca.pem"
#define CERT_FILE_CLIENT_KEY "/certs/client.key"
#define CERT_FILE_CLIENT_CERT "/certs/client.crt"

// Legacy NVS keys (for backwards compatibility during migration)
#define CERT_NVS_KEY_CA "ca_cert"
#define CERT_NVS_KEY_CLIENT_KEY "client_key"
#define CERT_NVS_KEY_CLIENT_CERT "client_cert"

class CertificateManager {
public:
    static CertificateManager& GetInstance() {
        static CertificateManager instance;
        return instance;
    }

    // Delete copy and move operations
    CertificateManager(const CertificateManager&) = delete;
    CertificateManager& operator=(const CertificateManager&) = delete;

    /**
     * Check if all required certificates exist in NVS
     * @return true if all three certificates are stored
     */
    bool HasCertificates();

    /**
     * Request certificates from server using HMAC-SHA256 signature
     * @return true if request successful and certificates are saved
     */
    bool RequestCertificates();

    /**
     * Get CA certificate from NVS
     * @return CA certificate in PEM format, or empty string if not found
     */
    std::string GetCaCert();

    /**
     * Get client private key from NVS
     * @return Client private key in PEM format, or empty string if not found
     */
    std::string GetClientKey();

    /**
     * Get client certificate from NVS
     * @return Client certificate in PEM format, or empty string if not found
     */
    std::string GetClientCert();

    /**
     * Clear all certificates from NVS
     */
    void ClearCertificates();

private:
    CertificateManager();
    ~CertificateManager();

    /**
     * Extract root URL from OTA URL (e.g., xxx/config -> xxx)
     * @param ota_url OTA URL that may contain a path suffix
     * @return Root URL without trailing slash
     */
    std::string ExtractRootUrl(const std::string& ota_url);

    /**
     * Generate HMAC-SHA256 signature for the request
     * @param client_id Device MAC address
     * @param timestamp Current timestamp in seconds
     * @return Hex-encoded signature string
     */
    std::string GenerateSignature(const std::string& client_id, uint64_t timestamp);

    /**
     * Save certificates to NVS
     * @param ca_cert CA certificate in PEM format
     * @param client_key Client private key in PEM format
     * @param client_cert Client certificate in PEM format
     * @return true if all certificates saved successfully
     */
    bool SaveCertificates(const std::string& ca_cert,
                          const std::string& client_key,
                          const std::string& client_cert);

    /**
     * Load certificates from NVS
     * @param ca_cert Output parameter for CA certificate
     * @param client_key Output parameter for client key
     * @param client_cert Output parameter for client certificate
     * @return true if all certificates loaded successfully
     */
    bool LoadCertificates(std::string& ca_cert,
                          std::string& client_key,
                          std::string& client_cert);
};

#endif // CERTIFICATE_MANAGER_H

