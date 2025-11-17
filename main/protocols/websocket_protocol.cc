#include "websocket_protocol.h"
#include "board.h"
#include "system_info.h"
#include "application.h"
#include "settings.h"
#include "certificate_manager.h"

#include <cstring>
#include <cJSON.h>
#include <esp_log.h>
#include <arpa/inet.h>
#include "assets/lang_config.h"

#define TAG "WS"

WebsocketProtocol::WebsocketProtocol() : websocket_client_(nullptr), connected_(false) {
    event_group_handle_ = xEventGroupCreate();
}

WebsocketProtocol::~WebsocketProtocol() {
    CloseAudioChannel();
    vEventGroupDelete(event_group_handle_);
}

bool WebsocketProtocol::Start() {
    // Only connect to server when audio channel is needed
    return true;
}

bool WebsocketProtocol::SendAudio(std::unique_ptr<AudioStreamPacket> packet) {
    if (!connected_ || websocket_client_ == nullptr) {
        return false;
    }

    if (version_ == 2) {
        std::string serialized;
        serialized.resize(sizeof(BinaryProtocol2) + packet->payload.size());
        auto bp2 = (BinaryProtocol2*)serialized.data();
        bp2->version = htons(version_);
        bp2->type = 0;
        bp2->reserved = 0;
        bp2->timestamp = htonl(packet->timestamp);
        bp2->payload_size = htonl(packet->payload.size());
        memcpy(bp2->payload, packet->payload.data(), packet->payload.size());

        int ret = esp_websocket_client_send_bin(websocket_client_, serialized.data(), 
                                                 serialized.size(), portMAX_DELAY);
        return ret > 0;
    } else if (version_ == 3) {
        std::string serialized;
        serialized.resize(sizeof(BinaryProtocol3) + packet->payload.size());
        auto bp3 = (BinaryProtocol3*)serialized.data();
        bp3->type = 0;
        bp3->reserved = 0;
        bp3->payload_size = htons(packet->payload.size());
        memcpy(bp3->payload, packet->payload.data(), packet->payload.size());

        int ret = esp_websocket_client_send_bin(websocket_client_, serialized.data(), 
                                                 serialized.size(), portMAX_DELAY);
        return ret > 0;
    } else {
        int ret = esp_websocket_client_send_bin(websocket_client_, 
                                                 (const char*)packet->payload.data(), 
                                                 packet->payload.size(), portMAX_DELAY);
        return ret > 0;
    }
}

bool WebsocketProtocol::SendText(const std::string& text) {
    if (!connected_ || websocket_client_ == nullptr) {
        return false;
    }

    int ret = esp_websocket_client_send_text(websocket_client_, text.c_str(), 
                                             text.length(), portMAX_DELAY);
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to send text: %s", text.c_str());
        SetError(Lang::Strings::SERVER_ERROR);
        return false;
    }

    return true;
}

bool WebsocketProtocol::IsAudioChannelOpened() const {
    return connected_ && websocket_client_ != nullptr && !error_occurred_ && !IsTimeout();
}

void WebsocketProtocol::CloseAudioChannel() {
    if (websocket_client_ != nullptr) {
        esp_websocket_client_stop(websocket_client_);
        esp_websocket_client_destroy(websocket_client_);
        websocket_client_ = nullptr;
    }
    connected_ = false;
}

bool WebsocketProtocol::OpenAudioChannel() {
    // Initialize mTLS certificates
    auto& cert_mgr = CertificateManager::GetInstance();
    
    if (!cert_mgr.HasCertificates()) {
        ESP_LOGW(TAG, "Certificates not found, requesting from server");
        if (!cert_mgr.RequestCertificates()) {
            ESP_LOGW(TAG, "Failed to request certificates, continuing without mTLS");
        }
    }
    
    // Load certificates for mTLS
    if (cert_mgr.HasCertificates()) {
        ca_cert_ = cert_mgr.GetCaCert();
        client_cert_ = cert_mgr.GetClientCert();
        client_key_ = cert_mgr.GetClientKey();
        ESP_LOGI(TAG, "mTLS certificates loaded: CA=%u bytes, cert=%u bytes, key=%u bytes", 
                 (unsigned int)ca_cert_.length(), (unsigned int)client_cert_.length(), (unsigned int)client_key_.length());
    } else {
        ESP_LOGW(TAG, "No certificates available!");
    }
    
    Settings settings("websocket", false);
    std::string url = settings.GetString("url");
    std::string token = settings.GetString("token");
    int version = settings.GetInt("version");
    if (version != 0) {
        version_ = version;
    }

    error_occurred_ = false;
    
    // Ensure URL has a path component (at least "/")
    // WebSocket requires a valid path, e.g., "wss://host/" not "wss://host"
    if (url.find("://") != std::string::npos) {
        size_t path_start = url.find('/', url.find("://") + 3);
        if (path_start == std::string::npos) {
            url += "/";  // Add trailing slash if no path specified
            ESP_LOGI(TAG, "Added trailing slash to WebSocket URL");
        }
    }
    
    ESP_LOGI(TAG, "WebSocket config: url=%s, version=%d, token_len=%u", 
             url.c_str(), version_, (unsigned int)token.length());

    // Prepare WebSocket configuration with mTLS support
    esp_websocket_client_config_t ws_cfg = {};
    ws_cfg.uri = url.c_str();
    ws_cfg.reconnect_timeout_ms = 10000;
    ws_cfg.network_timeout_ms = 10000;
    
    // Configure mTLS certificates
    // Note: ESP WebSocket client uses the same structure as HTTP client
    // PEM certificates must be null-terminated, use strlen() to get proper length
    if (!ca_cert_.empty()) {
        ws_cfg.cert_pem = ca_cert_.c_str();
        ws_cfg.cert_len = strlen(ca_cert_.c_str()) + 1;  // Include null terminator
        ESP_LOGI(TAG, "CA cert configured: %u bytes (strlen: %u)", 
                 (unsigned int)ca_cert_.length(), (unsigned int)strlen(ca_cert_.c_str()));
    } else {
        ESP_LOGW(TAG, "CA cert is empty!");
    }
    
    if (!client_cert_.empty() && !client_key_.empty()) {
        ws_cfg.client_cert = client_cert_.c_str();
        ws_cfg.client_cert_len = strlen(client_cert_.c_str()) + 1;  // Include null terminator
        ws_cfg.client_key = client_key_.c_str();
        ws_cfg.client_key_len = strlen(client_key_.c_str()) + 1;    // Include null terminator
        ESP_LOGI(TAG, "Client cert configured: cert=%u bytes (strlen: %u), key=%u bytes (strlen: %u)", 
                 (unsigned int)client_cert_.length(), (unsigned int)strlen(client_cert_.c_str()),
                 (unsigned int)client_key_.length(), (unsigned int)strlen(client_key_.c_str()));
    } else {
        ESP_LOGW(TAG, "Client cert or key is empty! cert: %u, key: %u", 
                 (unsigned int)client_cert_.length(), (unsigned int)client_key_.length());
    }
    
    // Configuration for self-signed certificates
    ws_cfg.skip_cert_common_name_check = true;  // Skip hostname verification for self-signed certs
    ws_cfg.use_global_ca_store = false;         // Use only provided CA cert, not global store
    
    ESP_LOGI(TAG, "Self-signed certificate support enabled");
    
    // Initialize WebSocket client
    websocket_client_ = esp_websocket_client_init(&ws_cfg);
    if (websocket_client_ == nullptr) {
        ESP_LOGE(TAG, "Failed to create websocket client");
        return false;
    }
    
    // Set custom headers (store in member variables to ensure lifetime)
    // Note: Store all header values in member variables to ensure they persist
    // during the async WebSocket connection process
    
    if (!token.empty()) {
        if (token.find(" ") == std::string::npos) {
            auth_header_ = "Bearer " + token;
        } else {
            auth_header_ = token;
        }
        ESP_LOGI(TAG, "Setting Authorization header");
        esp_websocket_client_append_header(websocket_client_, "Authorization", auth_header_.c_str());
    }
    
    protocol_version_header_ = std::to_string(version_);
    device_id_header_ = SystemInfo::GetMacAddress();
    client_id_header_ = Board::GetInstance().GetUuid();
    
    ESP_LOGI(TAG, "Setting custom headers: Protocol-Version=%s, Device-Id=%s, Client-Id=%s",
             protocol_version_header_.c_str(), device_id_header_.c_str(), client_id_header_.c_str());
    
    esp_websocket_client_append_header(websocket_client_, "Protocol-Version", protocol_version_header_.c_str());
    esp_websocket_client_append_header(websocket_client_, "Device-Id", device_id_header_.c_str());
    esp_websocket_client_append_header(websocket_client_, "Client-Id", client_id_header_.c_str());
    
    // Register event handler
    esp_websocket_register_events(websocket_client_, WEBSOCKET_EVENT_ANY, 
                                  WebsocketEventHandler, this);
    
    // Start WebSocket client
    ESP_LOGI(TAG, "Connecting to websocket server: %s with version: %d", url.c_str(), version_);
    esp_err_t ret = esp_websocket_client_start(websocket_client_);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start websocket client: %s", esp_err_to_name(ret));
        SetError(Lang::Strings::SERVER_NOT_CONNECTED);
        esp_websocket_client_destroy(websocket_client_);
        websocket_client_ = nullptr;
        return false;
    }

    // Note: Connection establishment and hello message exchange will be handled 
    // in the WEBSOCKET_EVENT_CONNECTED event handler
    // The client starts connecting asynchronously
    
    return true;
}

std::string WebsocketProtocol::GetHelloMessage() {
    // keys: message type, version, audio_params (format, sample_rate, channels)
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "hello");
    cJSON_AddNumberToObject(root, "version", version_);
    cJSON* features = cJSON_CreateObject();
#if CONFIG_USE_SERVER_AEC
    cJSON_AddBoolToObject(features, "aec", true);
#endif
    cJSON_AddBoolToObject(features, "mcp", true);
    cJSON_AddItemToObject(root, "features", features);
    cJSON_AddStringToObject(root, "transport", "websocket");
    cJSON* audio_params = cJSON_CreateObject();
    cJSON_AddStringToObject(audio_params, "format", "opus");
    cJSON_AddNumberToObject(audio_params, "sample_rate", 16000);
    cJSON_AddNumberToObject(audio_params, "channels", 1);
    cJSON_AddNumberToObject(audio_params, "frame_duration", OPUS_FRAME_DURATION_MS);
    cJSON_AddItemToObject(root, "audio_params", audio_params);
    auto json_str = cJSON_PrintUnformatted(root);
    std::string message(json_str);
    cJSON_free(json_str);
    cJSON_Delete(root);
    return message;
}

void WebsocketProtocol::ParseServerHello(const cJSON* root) {
    auto transport = cJSON_GetObjectItem(root, "transport");
    if (transport == nullptr || strcmp(transport->valuestring, "websocket") != 0) {
        ESP_LOGE(TAG, "Unsupported transport: %s", transport->valuestring);
        return;
    }

    auto session_id = cJSON_GetObjectItem(root, "session_id");
    if (cJSON_IsString(session_id)) {
        session_id_ = session_id->valuestring;
        ESP_LOGI(TAG, "Session ID: %s", session_id_.c_str());
    }

    auto audio_params = cJSON_GetObjectItem(root, "audio_params");
    if (cJSON_IsObject(audio_params)) {
        auto sample_rate = cJSON_GetObjectItem(audio_params, "sample_rate");
        if (cJSON_IsNumber(sample_rate)) {
            server_sample_rate_ = sample_rate->valueint;
        }
        auto frame_duration = cJSON_GetObjectItem(audio_params, "frame_duration");
        if (cJSON_IsNumber(frame_duration)) {
            server_frame_duration_ = frame_duration->valueint;
        }
    }

    xEventGroupSetBits(event_group_handle_, WEBSOCKET_PROTOCOL_SERVER_HELLO_EVENT);
    
    // Notify that audio channel is opened
    if (on_audio_channel_opened_ != nullptr) {
        on_audio_channel_opened_();
    }
}

void WebsocketProtocol::WebsocketEventHandler(void* handler_args, esp_event_base_t base, 
                                              int32_t event_id, void* event_data) {
    auto self = static_cast<WebsocketProtocol*>(handler_args);
    auto* data = static_cast<esp_websocket_event_data_t*>(event_data);
    
    switch (event_id) {
        case WEBSOCKET_EVENT_CONNECTED:
            ESP_LOGI(TAG, "WebSocket connected");
            self->connected_ = true;
            
            // Send hello message after connection is established
            {
                auto message = self->GetHelloMessage();
                int ret = esp_websocket_client_send_text(self->websocket_client_, 
                                                         message.c_str(), 
                                                         message.length(), 
                                                         portMAX_DELAY);
                if (ret < 0) {
                    ESP_LOGE(TAG, "Failed to send hello message");
                    self->SetError(Lang::Strings::SERVER_ERROR);
                }
            }
            break;
            
        case WEBSOCKET_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "WebSocket disconnected");
            self->connected_ = false;
            if (self->on_audio_channel_closed_ != nullptr) {
                self->on_audio_channel_closed_();
            }
            break;
            
        case WEBSOCKET_EVENT_DATA:
            self->last_incoming_time_ = std::chrono::steady_clock::now();
            
            if (data->op_code == 0x02) {  // Binary data
                if (self->on_incoming_audio_ != nullptr) {
                    const char* payload_data = data->data_ptr;
                    size_t payload_len = data->data_len;
                    
                    if (self->version_ == 2) {
                        BinaryProtocol2* bp2 = (BinaryProtocol2*)payload_data;
                        bp2->version = ntohs(bp2->version);
                        bp2->type = ntohs(bp2->type);
                        bp2->timestamp = ntohl(bp2->timestamp);
                        bp2->payload_size = ntohl(bp2->payload_size);
                        auto payload = (uint8_t*)bp2->payload;
                        self->on_incoming_audio_(std::make_unique<AudioStreamPacket>(AudioStreamPacket{
                            .sample_rate = self->server_sample_rate_,
                            .frame_duration = self->server_frame_duration_,
                            .timestamp = bp2->timestamp,
                            .payload = std::vector<uint8_t>(payload, payload + bp2->payload_size)
                        }));
                    } else if (self->version_ == 3) {
                        BinaryProtocol3* bp3 = (BinaryProtocol3*)payload_data;
                        bp3->type = bp3->type;
                        bp3->payload_size = ntohs(bp3->payload_size);
                        auto payload = (uint8_t*)bp3->payload;
                        self->on_incoming_audio_(std::make_unique<AudioStreamPacket>(AudioStreamPacket{
                            .sample_rate = self->server_sample_rate_,
                            .frame_duration = self->server_frame_duration_,
                            .timestamp = 0,
                            .payload = std::vector<uint8_t>(payload, payload + bp3->payload_size)
                        }));
                    } else {
                        self->on_incoming_audio_(std::make_unique<AudioStreamPacket>(AudioStreamPacket{
                            .sample_rate = self->server_sample_rate_,
                            .frame_duration = self->server_frame_duration_,
                            .timestamp = 0,
                            .payload = std::vector<uint8_t>((uint8_t*)payload_data, 
                                                           (uint8_t*)payload_data + payload_len)
                        }));
                    }
                }
            } else if (data->op_code == 0x01) {  // Text data
                // Parse JSON data
                auto root = cJSON_Parse(data->data_ptr);
                if (root != nullptr) {
                    auto type = cJSON_GetObjectItem(root, "type");
                    if (cJSON_IsString(type)) {
                        if (strcmp(type->valuestring, "hello") == 0) {
                            self->ParseServerHello(root);
                        } else {
                            if (self->on_incoming_json_ != nullptr) {
                                self->on_incoming_json_(root);
                            }
                        }
                    } else {
                        ESP_LOGE(TAG, "Missing message type");
                    }
                    cJSON_Delete(root);
                }
            }
            break;
            
        case WEBSOCKET_EVENT_ERROR:
            ESP_LOGE(TAG, "WebSocket error");
            break;
            
        default:
            break;
    }
}
