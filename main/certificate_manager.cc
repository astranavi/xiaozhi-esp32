#include "certificate_manager.h"
#include "settings.h"
#include "system_info.h"
#include "board.h"

#include <esp_log.h>
#include <cJSON.h>
#include <time.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <mbedtls/md.h>
#include <http.h>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <cstdio>
#include <esp_spiffs.h>
#include <esp_partition.h>

#define TAG "CertMgr"

// Static function to initialize SPIFFS for certificate storage
static void EnsureSpiffsInitialized() {
    static bool spiffs_initialized = false;
    
    if (spiffs_initialized) {
        return;
    }
    
    // Check if the certs partition exists
    const esp_partition_t *partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, "certs");
    
    if (partition == nullptr) {
        ESP_LOGE(TAG, "Certs partition not found! Please update partition table and run: idf.py erase-flash && idf.py flash");
        spiffs_initialized = false;
        return;
    }
    
    esp_vfs_spiffs_conf_t spiffs_conf = {
        .base_path = "/certs",
        .partition_label = "certs",
        .max_files = 5,
        .format_if_mount_failed = true
    };
    
    esp_err_t ret = esp_vfs_spiffs_register(&spiffs_conf);
    
    if (ret == ESP_OK) {
        spiffs_initialized = true;
        return;
    }
    
    ESP_LOGE(TAG, "Failed to mount certs partition: %s", esp_err_to_name(ret));
    spiffs_initialized = false;
}

CertificateManager::CertificateManager() {
    EnsureSpiffsInitialized();
}

CertificateManager::~CertificateManager() {
}

std::string CertificateManager::ExtractRootUrl(const std::string& ota_url) {
    // Extract root URL from OTA URL
    // Example: "https://example.com/config" -> "https://example.com"
    // Example: "https://example.com/" -> "https://example.com"
    // Example: "https://example.com" -> "https://example.com"
    
    if (ota_url.empty()) {
        return ota_url;
    }
    
    std::string url = ota_url;
    
    // Remove trailing slash if present
    if (url.back() == '/') {
        url.pop_back();
    }
    
    // Find the last slash to determine where the path begins
    size_t last_slash = url.rfind('/');
    if (last_slash != std::string::npos) {
        // Find the third slash (after protocol://)
        size_t protocol_end = url.find("://");
        if (protocol_end != std::string::npos) {
            protocol_end += 3;  // Move past "://"
            size_t first_slash_after_protocol = url.find('/', protocol_end);
            
            if (first_slash_after_protocol != std::string::npos) {
                // There is a path component, remove it
                url = url.substr(0, first_slash_after_protocol);
            }
        }
    }
    
    ESP_LOGI(TAG, "Extracted root URL: %s", url.c_str());
    return url;
}

bool CertificateManager::HasCertificates() {
    struct stat buffer;
    bool ca_exists = stat(CERT_FILE_CA, &buffer) == 0;
    bool key_exists = stat(CERT_FILE_CLIENT_KEY, &buffer) == 0;
    bool cert_exists = stat(CERT_FILE_CLIENT_CERT, &buffer) == 0;
    
    return ca_exists && key_exists && cert_exists;
}

std::string CertificateManager::GenerateSignature(const std::string& client_id, uint64_t timestamp) {
    // Format: client_id:timestamp
    std::string data = client_id + ":" + std::to_string(timestamp);
    
    ESP_LOGI(TAG, "Generating signature for: %s", data.c_str());
    
    // Calculate HMAC-SHA256
    unsigned char hmac_output[32];  // SHA-256 output is 32 bytes
    
    const unsigned char* key = (const unsigned char*)MTLS_SECRET;
    size_t key_len = strlen(MTLS_SECRET);
    
    // Use mbedtls for HMAC-SHA256
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    
    int ret = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to setup HMAC context: %d", ret);
        mbedtls_md_free(&ctx);
        return "";
    }
    
    ret = mbedtls_md_hmac_starts(&ctx, key, key_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to start HMAC: %d", ret);
        mbedtls_md_free(&ctx);
        return "";
    }
    
    ret = mbedtls_md_hmac_update(&ctx, (const unsigned char*)data.c_str(), data.length());
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to update HMAC: %d", ret);
        mbedtls_md_free(&ctx);
        return "";
    }
    
    ret = mbedtls_md_hmac_finish(&ctx, hmac_output);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to finish HMAC: %d", ret);
        mbedtls_md_free(&ctx);
        return "";
    }
    
    mbedtls_md_free(&ctx);
    
    // Convert to hex string
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hmac_output[i];
    }
    
    return ss.str();
}

bool CertificateManager::RequestCertificates() {
    // Get client ID from MAC address
    std::string client_id = SystemInfo::GetMacAddress();
    if (client_id.empty()) {
        ESP_LOGE(TAG, "Failed to get MAC address");
        return false;
    }
    
    // Get current timestamp
    time_t now = time(nullptr);
    uint64_t timestamp = (uint64_t)now;
    
    ESP_LOGI(TAG, "Requesting certificates for client_id: %s, timestamp: %llu", 
             client_id.c_str(), timestamp);
    
    // Generate signature
    std::string signature = GenerateSignature(client_id, timestamp);
    if (signature.empty()) {
        ESP_LOGE(TAG, "Failed to generate signature");
        return false;
    }
    
    ESP_LOGI(TAG, "Generated signature: %s", signature.c_str());
    
    // Create request JSON
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "client_id", client_id.c_str());
    cJSON_AddNumberToObject(root, "timestamp", timestamp);
    cJSON_AddStringToObject(root, "signature", signature.c_str());
    
    char* json_str = cJSON_PrintUnformatted(root);
    std::string request_body(json_str);
    cJSON_free(json_str);
    cJSON_Delete(root);
    
    ESP_LOGI(TAG, "Request body: %s", request_body.c_str());
    
    // Make HTTP request
    auto& board = Board::GetInstance();
    auto network = board.GetNetwork();
    auto http = network->CreateHttp(0);
    
    if (http == nullptr) {
        ESP_LOGE(TAG, "Failed to create HTTP client");
        return false;
    }
    
    // Set headers
    http->SetHeader("Content-Type", "application/json");
    http->SetContent(std::move(request_body));
    
    // Get OTA URL and extract root URL
    Settings wifi_settings("wifi", false);
    std::string ota_url = wifi_settings.GetString("ota_url");
    if (ota_url.empty()) {
        ota_url = CONFIG_OTA_URL;
    }
    
    // Extract root URL (e.g., xxx/config -> xxx)
    std::string root_url = ExtractRootUrl(ota_url);
    
    // Construct cert request URL: root_url + /cert/sign
    std::string cert_url = root_url;
    if (cert_url.back() != '/') {
        cert_url += "/";
    }
    cert_url += "cert/sign";  // Append certificate request path
    
    ESP_LOGI(TAG, "Making request to: %s", cert_url.c_str());
    
    if (!http->Open("POST", cert_url)) {
        ESP_LOGE(TAG, "Failed to open HTTP connection");
        return false;
    }
    
    int status_code = http->GetStatusCode();
    
    if (status_code != 200) {
        ESP_LOGE(TAG, "Failed to get certificates, status code: %d", status_code);
        std::string response = http->ReadAll();
        ESP_LOGE(TAG, "Response: %s", response.c_str());
        return false;
    }
    
    // Parse response
    std::string response = http->ReadAll();
    ESP_LOGI(TAG, "Fetched certificates successfully");
    
    cJSON* resp_root = cJSON_Parse(response.c_str());
    if (resp_root == nullptr) {
        ESP_LOGE(TAG, "Failed to parse response JSON");
        return false;
    }
    
    cJSON* code_item = cJSON_GetObjectItem(resp_root, "code");
    cJSON* client_key_item = cJSON_GetObjectItem(resp_root, "client_key");
    cJSON* client_crt_item = cJSON_GetObjectItem(resp_root, "client_crt");
    cJSON* root_cert_item = cJSON_GetObjectItem(resp_root, "root_cert");
    
    if (!cJSON_IsNumber(code_item) || code_item->valueint != 200) {
        ESP_LOGE(TAG, "Invalid response code");
        cJSON_Delete(resp_root);
        return false;
    }
    
    if (!cJSON_IsString(client_key_item) || !cJSON_IsString(client_crt_item) || !cJSON_IsString(root_cert_item)) {
        ESP_LOGE(TAG, "Missing certificate fields in response");
        cJSON_Delete(resp_root);
        return false;
    }
    
    std::string client_key = client_key_item->valuestring;
    std::string client_crt = client_crt_item->valuestring;
    std::string root_cert = root_cert_item->valuestring;
    
    cJSON_Delete(resp_root);
    
    // Save certificates to NVS
    bool saved = SaveCertificates(root_cert, client_key, client_crt);
    
    if (saved) {
        ESP_LOGI(TAG, "Certificates successfully saved");
    } else {
        ESP_LOGE(TAG, "Failed to save certificates");
    }
    
    return saved;
}

bool CertificateManager::SaveCertificates(const std::string& ca_cert,
                                          const std::string& client_key,
                                          const std::string& client_cert) {
    try {
        // Save CA certificate
        FILE* ca_fp = fopen(CERT_FILE_CA, "wb");
        if (!ca_fp) {
            ESP_LOGE(TAG, "Failed to open CA certificate file: %d (%s)", errno, strerror(errno));
            return false;
        }
        size_t written = fwrite(ca_cert.c_str(), 1, ca_cert.length(), ca_fp);
        if (written != ca_cert.length()) {
            ESP_LOGE(TAG, "Failed to write CA certificate, wrote %zu of %zu bytes", written, ca_cert.length());
            fclose(ca_fp);
            return false;
        }
        fclose(ca_fp);
        
        // Save client key
        FILE* key_fp = fopen(CERT_FILE_CLIENT_KEY, "wb");
        if (!key_fp) {
            ESP_LOGE(TAG, "Failed to open client key file for writing: %d", errno);
            return false;
        }
        written = fwrite(client_key.c_str(), 1, client_key.length(), key_fp);
        if (written != client_key.length()) {
            ESP_LOGE(TAG, "Failed to write client key, wrote %zu of %zu bytes", written, client_key.length());
            fclose(key_fp);
            return false;
        }
        fclose(key_fp);
        
        // Save client certificate
        FILE* cert_fp = fopen(CERT_FILE_CLIENT_CERT, "wb");
        if (!cert_fp) {
            ESP_LOGE(TAG, "Failed to open client certificate file for writing: %d", errno);
            return false;
        }
        written = fwrite(client_cert.c_str(), 1, client_cert.length(), cert_fp);
        if (written != client_cert.length()) {
            ESP_LOGE(TAG, "Failed to write client certificate, wrote %zu of %zu bytes", written, client_cert.length());
            fclose(cert_fp);
            return false;
        }
        fclose(cert_fp);
        
        ESP_LOGI(TAG, "Certificates saved (ca: %u, key: %u, cert: %u bytes)",
                 (unsigned int)ca_cert.length(), (unsigned int)client_key.length(), (unsigned int)client_cert.length());
        
        return true;
    } catch (...) {
        ESP_LOGE(TAG, "Exception occurred while saving certificates");
        return false;
    }
}

bool CertificateManager::LoadCertificates(std::string& ca_cert,
                                          std::string& client_key,
                                          std::string& client_cert) {
    try {
        // Load CA certificate from file
        FILE* ca_fp = fopen(CERT_FILE_CA, "rb");
        if (!ca_fp) {
            ESP_LOGE(TAG, "Failed to open CA certificate file for reading: %d", errno);
            return false;
        }
        fseek(ca_fp, 0, SEEK_END);
        size_t ca_size = ftell(ca_fp);
        fseek(ca_fp, 0, SEEK_SET);
        ca_cert.resize(ca_size);
        size_t read_count = fread(&ca_cert[0], 1, ca_size, ca_fp);
        fclose(ca_fp);
        if (read_count != ca_size) {
            ESP_LOGE(TAG, "Failed to read CA certificate, read %zu of %zu bytes", read_count, ca_size);
            return false;
        }
        
        // Load client key
        FILE* key_fp = fopen(CERT_FILE_CLIENT_KEY, "rb");
        if (!key_fp) {
            ESP_LOGE(TAG, "Failed to open client key file for reading: %d", errno);
            return false;
        }
        fseek(key_fp, 0, SEEK_END);
        size_t key_size = ftell(key_fp);
        fseek(key_fp, 0, SEEK_SET);
        client_key.resize(key_size);
        read_count = fread(&client_key[0], 1, key_size, key_fp);
        fclose(key_fp);
        if (read_count != key_size) {
            ESP_LOGE(TAG, "Failed to read client key, read %zu of %zu bytes", read_count, key_size);
            return false;
        }
        
        // Load client certificate
        FILE* cert_fp = fopen(CERT_FILE_CLIENT_CERT, "rb");
        if (!cert_fp) {
            ESP_LOGE(TAG, "Failed to open client certificate file for reading: %d", errno);
            return false;
        }
        fseek(cert_fp, 0, SEEK_END);
        size_t cert_size = ftell(cert_fp);
        fseek(cert_fp, 0, SEEK_SET);
        client_cert.resize(cert_size);
        read_count = fread(&client_cert[0], 1, cert_size, cert_fp);
        fclose(cert_fp);
        if (read_count != cert_size) {
            ESP_LOGE(TAG, "Failed to read client certificate, read %zu of %zu bytes", read_count, cert_size);
            return false;
        }
        
        bool has_all = !ca_cert.empty() && !client_key.empty() && !client_cert.empty();
        
        if (!has_all) {
            ESP_LOGE(TAG, "Failed to load all certificates");
        }
        
        return has_all;
    } catch (...) {
        ESP_LOGE(TAG, "Exception occurred while loading certificates");
        return false;
    }
}

std::string CertificateManager::GetCaCert() {
    try {
        std::ifstream ca_file(CERT_FILE_CA, std::ios::binary);
        if (!ca_file.is_open()) {
            ESP_LOGW(TAG, "CA certificate file not found");
            return "";
        }
        ca_file.seekg(0, std::ios::end);
        size_t size = ca_file.tellg();
        ca_file.seekg(0, std::ios::beg);
        std::string content(size, '\0');
        ca_file.read(&content[0], size);
        ca_file.close();
        
        // Ensure null termination for PEM parsing
        if (!content.empty() && content.back() != '\0') {
            content.push_back('\0');
        }
        
        return content;
    } catch (...) {
        ESP_LOGE(TAG, "Exception occurred while reading CA certificate");
        return "";
    }
}

std::string CertificateManager::GetClientKey() {
    try {
        std::ifstream key_file(CERT_FILE_CLIENT_KEY, std::ios::binary);
        if (!key_file.is_open()) {
            ESP_LOGW(TAG, "Client key file not found");
            return "";
        }
        key_file.seekg(0, std::ios::end);
        size_t size = key_file.tellg();
        key_file.seekg(0, std::ios::beg);
        std::string content(size, '\0');
        key_file.read(&content[0], size);
        key_file.close();
        
        // Ensure null termination for PEM parsing
        if (!content.empty() && content.back() != '\0') {
            content.push_back('\0');
        }
        
        return content;
    } catch (...) {
        ESP_LOGE(TAG, "Exception occurred while reading client key");
        return "";
    }
}

std::string CertificateManager::GetClientCert() {
    try {
        std::ifstream cert_file(CERT_FILE_CLIENT_CERT, std::ios::binary);
        if (!cert_file.is_open()) {
            ESP_LOGW(TAG, "Client certificate file not found");
            return "";
        }
        cert_file.seekg(0, std::ios::end);
        size_t size = cert_file.tellg();
        cert_file.seekg(0, std::ios::beg);
        std::string content(size, '\0');
        cert_file.read(&content[0], size);
        cert_file.close();
        
        // Ensure null termination for PEM parsing
        if (!content.empty() && content.back() != '\0') {
            content.push_back('\0');
        }
        
        return content;
    } catch (...) {
        ESP_LOGE(TAG, "Exception occurred while reading client certificate");
        return "";
    }
}

void CertificateManager::ClearCertificates() {
    // Delete certificate files from SPIFFS
    int ret;
    
    ret = unlink(CERT_FILE_CA);
    if (ret == 0) {
        ESP_LOGI(TAG, "Deleted CA certificate file");
    } else if (errno != ENOENT) {
        ESP_LOGW(TAG, "Failed to delete CA certificate file: %d", errno);
    }
    
    ret = unlink(CERT_FILE_CLIENT_KEY);
    if (ret == 0) {
        ESP_LOGI(TAG, "Deleted client key file");
    } else if (errno != ENOENT) {
        ESP_LOGW(TAG, "Failed to delete client key file: %d", errno);
    }
    
    ret = unlink(CERT_FILE_CLIENT_CERT);
    if (ret == 0) {
        ESP_LOGI(TAG, "Deleted client certificate file");
    } else if (errno != ENOENT) {
        ESP_LOGW(TAG, "Failed to delete client certificate file: %d", errno);
    }
    
    ESP_LOGI(TAG, "Certificates cleared");
}

