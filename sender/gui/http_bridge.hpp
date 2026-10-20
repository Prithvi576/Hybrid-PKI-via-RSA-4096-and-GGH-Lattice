#ifndef SENDER_HTTP_BRIDGE_HPP
#define SENDER_HTTP_BRIDGE_HPP

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "../machines/machine_manager.hpp"
#include "../messaging/message_store.hpp"
#include "../models/machine_model.hpp"
#include "../models/message_model.hpp"
#include "../networking/sender_network.hpp"
#include "../storage/local_storage.hpp"
#include "crypto_api.hpp"

namespace sender {

class HttpBridge {
public:
    HttpBridge(LocalStorage& storage,
               MachineManager& machines,
               MessageStore& messages,
               const std::string& assets_dir,
               uint16_t port = 18443);
    ~HttpBridge();

    bool start();
    void stop();
    uint16_t port() const { return port_; }
    std::string rootUrl() const;

private:
    void listenLoop();
    void handleClient(SOCKET client_sock);
    void handleRequest(const std::string& method,
                       const std::string& raw_path,
                       const std::string& body,
                       std::string& status_code,
                       std::string& content_type,
                       std::string& response_body);

    LocalStorage& storage_;
    MachineManager& machines_;
    MessageStore& messages_;
    std::string assets_dir_;
    uint16_t port_;
    SOCKET listen_sock_{INVALID_SOCKET};
    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> thread_;
};

}  // namespace sender

#endif  // SENDER_HTTP_BRIDGE_HPP
