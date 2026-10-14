#ifndef SENDER_NETWORK_HPP
#define SENDER_NETWORK_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace sender {

enum class ConnectResult { Success, Failed };
enum class SendResult { Success, Failed, Disconnected };

class TcpClient {
public:
    TcpClient();
    ~TcpClient();

    TcpClient(const TcpClient&) = delete;
    TcpClient& operator=(const TcpClient&) = delete;

    ConnectResult connect(const std::string& hostname, uint16_t port,
                          int timeout_ms = 3000);
    SendResult sendFrame(const std::vector<unsigned char>& data);
    void disconnect();
    bool connected() const { return socket_ != static_cast<uintptr_t>(-1); }

private:
    uintptr_t socket_;
    static bool wsa_initialized_;
    static void ensureWsa();
};

std::vector<unsigned char> frameMessage(const std::string& command,
                                         const std::string& timestamp_utc,
                                         uint64_t sequence,
                                         const std::vector<unsigned char>& rsa_sig,
                                         const std::vector<int64_t>& ggh_lattice_point);

}  // namespace sender

#endif
