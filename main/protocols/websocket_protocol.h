#ifndef _WEBSOCKET_PROTOCOL_H_
#define _WEBSOCKET_PROTOCOL_H_

#include "protocol.h"

#include <string>
#include <esp_websocket_client.h>
#include <esp_event.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>

#define WEBSOCKET_PROTOCOL_SERVER_HELLO_EVENT (1 << 0)

class WebsocketProtocol : public Protocol {
public:
    WebsocketProtocol();
    ~WebsocketProtocol();

    bool Start() override;
    bool SendAudio(std::unique_ptr<AudioStreamPacket> packet) override;
    bool OpenAudioChannel() override;
    void CloseAudioChannel() override;
    bool IsAudioChannelOpened() const override;

private:
    EventGroupHandle_t event_group_handle_;
    esp_websocket_client_handle_t websocket_client_;
    bool connected_;
    int version_ = 1;
    
    // Certificate storage for mTLS
    std::string ca_cert_;
    std::string client_cert_;
    std::string client_key_;
    
    // Header storage (must persist for WebSocket client lifetime)
    std::string auth_header_;
    std::string protocol_version_header_;
    std::string device_id_header_;
    std::string client_id_header_;

    void ParseServerHello(const cJSON* root);
    bool SendText(const std::string& text) override;
    std::string GetHelloMessage();
    
    static void WebsocketEventHandler(void* handler_args, esp_event_base_t base, 
                                     int32_t event_id, void* event_data);
};

#endif
