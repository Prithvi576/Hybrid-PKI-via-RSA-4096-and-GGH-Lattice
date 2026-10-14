#include "sender_network.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <stdexcept>

using namespace std;

namespace sender {

bool TcpClient::wsa_initialized_ = false;

void TcpClient::ensureWsa() {
    if (wsa_initialized_) return;
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        throw runtime_error("WSAStartup failed");
    }
    wsa_initialized_ = true;
}

TcpClient::TcpClient() : socket_(static_cast<uintptr_t>(INVALID_SOCKET)) {
    ensureWsa();
}

TcpClient::~TcpClient() {
    disconnect();
}

ConnectResult TcpClient::connect(const string& hostname, uint16_t port,
                                 int timeout_ms) {
    disconnect();

    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    string port_str = to_string(port);
    if (getaddrinfo(hostname.c_str(), port_str.c_str(), &hints, &result) != 0) {
        return ConnectResult::Failed;
    }

    SOCKET sock = INVALID_SOCKET;
    for (auto* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock == INVALID_SOCKET) continue;

        // Set non-blocking for timeout
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        int res = ::connect(sock, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen));
        if (res == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(sock, &wfds);
                struct timeval tv;
                tv.tv_sec = timeout_ms / 1000;
                tv.tv_usec = (timeout_ms % 1000) * 1000;
                if (select(0, nullptr, &wfds, nullptr, &tv) > 0) {
                    int optval = 0;
                    int optlen = sizeof(optval);
                    getsockopt(sock, SOL_SOCKET, SO_ERROR,
                               reinterpret_cast<char*>(&optval), &optlen);
                    if (optval == 0) {
                        mode = 0;
                        ioctlsocket(sock, FIONBIO, &mode);
                        socket_ = static_cast<uintptr_t>(sock);
                        freeaddrinfo(result);
                        return ConnectResult::Success;
                    }
                }
            }
            closesocket(sock);
            sock = INVALID_SOCKET;
            continue;
        }
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        socket_ = static_cast<uintptr_t>(sock);
        freeaddrinfo(result);
        return ConnectResult::Success;
    }

    freeaddrinfo(result);
    return ConnectResult::Failed;
}

SendResult TcpClient::sendFrame(const vector<unsigned char>& data) {
    if (!connected()) return SendResult::Disconnected;

    SOCKET sock = static_cast<SOCKET>(socket_);

    // Length-prefixed framing: 4-byte big-endian length + payload
    uint32_t length = static_cast<uint32_t>(data.size());
    unsigned char header[4];
    header[0] = static_cast<unsigned char>((length >> 24) & 0xFF);
    header[1] = static_cast<unsigned char>((length >> 16) & 0xFF);
    header[2] = static_cast<unsigned char>((length >> 8) & 0xFF);
    header[3] = static_cast<unsigned char>(length & 0xFF);

    // Send header
    int total = 0;
    while (total < 4) {
        int sent = send(sock, reinterpret_cast<const char*>(header + total),
                        4 - total, 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            disconnect();
            return SendResult::Failed;
        }
        total += sent;
    }

    // Send payload
    size_t payload_sent = 0;
    while (payload_sent < data.size()) {
        int chunk = static_cast<int>(min(data.size() - payload_sent, size_t(65536)));
        int sent = send(sock, reinterpret_cast<const char*>(data.data() + payload_sent),
                        chunk, 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            disconnect();
            return SendResult::Failed;
        }
        payload_sent += static_cast<size_t>(sent);
    }

    return SendResult::Success;
}

void TcpClient::disconnect() {
    if (socket_ != static_cast<uintptr_t>(INVALID_SOCKET)) {
        shutdown(static_cast<SOCKET>(socket_), SD_BOTH);
        closesocket(static_cast<SOCKET>(socket_));
        socket_ = static_cast<uintptr_t>(INVALID_SOCKET);
    }
}

// Serialize a signed command into a binary frame.
// Format: [cmd_len:4][cmd][ts_len:4][ts][seq:8][rsa_len:4][rsa_sig][ggh_dim:4][ggh_values:dim*8]
vector<unsigned char> frameMessage(const string& command,
                                    const string& timestamp_utc,
                                    uint64_t sequence,
                                    const vector<unsigned char>& rsa_sig,
                                    const vector<int64_t>& ggh_lattice_point) {
    vector<unsigned char> frame;
    auto pushU32 = [&](uint32_t v) {
        frame.push_back(static_cast<unsigned char>((v >> 24) & 0xFF));
        frame.push_back(static_cast<unsigned char>((v >> 16) & 0xFF));
        frame.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
        frame.push_back(static_cast<unsigned char>(v & 0xFF));
    };
    auto pushU64 = [&](uint64_t v) {
        for (int i = 56; i >= 0; i -= 8)
            frame.push_back(static_cast<unsigned char>((v >> i) & 0xFF));
    };
    auto pushStr = [&](const string& s) {
        pushU32(static_cast<uint32_t>(s.size()));
        frame.insert(frame.end(), s.begin(), s.end());
    };

    pushStr(command);
    pushStr(timestamp_utc);
    pushU64(sequence);
    pushU32(static_cast<uint32_t>(rsa_sig.size()));
    frame.insert(frame.end(), rsa_sig.begin(), rsa_sig.end());
    pushU32(static_cast<uint32_t>(ggh_lattice_point.size()));
    for (int64_t v : ggh_lattice_point) {
        pushU64(static_cast<uint64_t>(v));
    }
    return frame;
}

}  // namespace sender
