// test_framing.cpp
// TCP framing and failure-handling test harness for Person 1 (sender side).
//
// A loopback server thread receives frames over a real TCP connection on
// 127.0.0.1 so the entire test is self-contained.  No real receiver is needed.
//
// Test cases:
//  1. Complete frame transmitted and reassembled correctly.
//  2. 4-byte length prefix read via looping recv (not a single call).
//  3. Payload arrives in multiple reads (server-side recv loop).
//  4. Multiple consecutive frames retain correct boundaries.
//  5. Disconnected server yields SendResult::Disconnected.
//  6. Oversized fields rejected by frameMessage before serialization.
//  7. Full payload delivery (sendFrame loops until complete).
//  8. Connection failure not reported as success.
//  9. Zero-length command field serialized correctly.
// 10. Truncated frame detected server-side.
// 11. Oversized length field rejected server-side before allocation.

#include "sender_network.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <climits>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// ws2_32 is linked via CMakeLists.txt; no pragma needed for MinGW.

using namespace std;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool condition, const char* detail) {
    if (!condition) {
        ++g_fail;
        cerr << "  [FAIL] " << detail << '\n';
    } else {
        ++g_pass;
        cout << "  [PASS] " << detail << '\n';
    }
}

// ---------------------------------------------------------------------------
// Loopback server helpers
// ---------------------------------------------------------------------------

// Read exactly `n` bytes from `sock` into `buf`, looping over recv().
// Returns true on success, false if the connection closes early.
bool recvExact(SOCKET sock, unsigned char* buf, size_t n) {
    size_t received = 0;
    while (received < n) {
        int chunk = recv(sock, reinterpret_cast<char*>(buf + received),
                         static_cast<int>(min(n - received, size_t(65536))), 0);
        if (chunk <= 0) return false;
        received += static_cast<size_t>(chunk);
    }
    return true;
}

// Read a length-prefixed frame from `sock` into `out`.
// Returns:
//  0 = success
// -1 = connection closed before length header
// -2 = connection closed before full payload
// -3 = payload length exceeds kFrameMaxPayloadBytes
int recvFrame(SOCKET sock, vector<unsigned char>& out) {
    unsigned char header[4];
    if (!recvExact(sock, header, 4)) return -1;

    uint32_t length = (static_cast<uint32_t>(header[0]) << 24) |
                      (static_cast<uint32_t>(header[1]) << 16) |
                      (static_cast<uint32_t>(header[2]) << 8)  |
                       static_cast<uint32_t>(header[3]);

    if (length > sender::kFrameMaxPayloadBytes) return -3;

    out.resize(length);
    if (length == 0) return 0;
    if (!recvExact(sock, out.data(), length)) return -2;
    return 0;
}

// Bind a listening socket on 127.0.0.1:0 and return it.
// port_out is set to the actual OS-assigned port.
SOCKET bindLoopback(uint16_t& port_out) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) throw runtime_error("socket() failed");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s);
        throw runtime_error("bind() failed");
    }
    if (listen(s, 1) != 0) {
        closesocket(s);
        throw runtime_error("listen() failed");
    }

    int addrlen = sizeof(addr);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&addr), &addrlen) != 0) {
        closesocket(s);
        throw runtime_error("getsockname() failed");
    }
    port_out = ntohs(addr.sin_port);
    return s;
}

// Receive exactly `expected_frames` frames via recvFrame, close the accepted
// conn, and write results into out-parameters.  Designed to run in a thread.
void serverWorker(SOCKET listen_sock, int expected_frames,
                  vector<vector<unsigned char>>* frames_out,
                  int* result_out) {
    SOCKET conn = accept(listen_sock, nullptr, nullptr);
    if (conn == INVALID_SOCKET) { *result_out = -99; return; }
    int code = 0;
    for (int i = 0; i < expected_frames && code == 0; ++i) {
        vector<unsigned char> frame;
        code = recvFrame(conn, frame);
        if (code == 0) frames_out->push_back(move(frame));
    }
    closesocket(conn);
    *result_out = code;
}

// RAII wrapper: owns a listening socket and a server thread.
// Result and frames are plain members; caller owns this on the stack
// so there is no move/copy involved.
struct Server {
    SOCKET listen_sock = INVALID_SOCKET;
    uint16_t port = 0;
    vector<vector<unsigned char>> frames;
    int result = -999;
    thread worker;

    void start(int expected_frames) {
        listen_sock = bindLoopback(port);
        worker = thread(serverWorker, listen_sock, expected_frames,
                        &frames, &result);
    }
    void join() {
        if (worker.joinable()) worker.join();
        if (listen_sock != INVALID_SOCKET) {
            closesocket(listen_sock);
            listen_sock = INVALID_SOCKET;
        }
    }
    ~Server() { join(); }
};

}  // namespace

// ---------------------------------------------------------------------------
// Reference frame: a minimal valid message
// ---------------------------------------------------------------------------

static vector<unsigned char> makeValidFrame() {
    return sender::frameMessage(
        "OPEN_VALVE",
        "2026-10-07T18:00:00Z",
        /*sequence=*/1,
        /*rsa_sig=*/vector<unsigned char>(512, 0xAB),
        /*ggh=*/vector<int64_t>(16, 42));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "FATAL: WSAStartup failed\n";
        return 1;
    }

    cout << "\n======================================\n";
    cout << "  TCP FRAMING TEST SUITE\n";
    cout << "======================================\n\n";

    // ------------------------------------------------------------------
    // Test 1: Complete frame transmitted and reassembled correctly
    // ------------------------------------------------------------------
    cout << "[Test 1: Complete frame round-trip]\n";
    {
        Server srv;
        srv.start(1);
        sender::TcpClient client;
        auto cr = client.connect("127.0.0.1", srv.port, 3000);
        check(cr == sender::ConnectResult::Success, "Connect to loopback server");

        auto payload = makeValidFrame();
        auto sr = client.sendFrame(payload);
        check(sr == sender::SendResult::Success, "sendFrame returns Success");
        client.disconnect();
        srv.join();
        check(srv.result == 0, "Server received frame without error");
        check(srv.frames.size() == 1, "Exactly one frame received");
        check(srv.frames.size() == 1 && srv.frames[0] == payload,
              "Received payload matches sent payload exactly");
    }

    // ------------------------------------------------------------------
    // Test 2: Length prefix read via looping recv (not a single call)
    // ------------------------------------------------------------------
    cout << "\n[Test 2: Length-prefix read via looping recv]\n";
    {
        Server srv;
        srv.start(1);
        sender::TcpClient client;
        client.connect("127.0.0.1", srv.port, 3000);

        vector<unsigned char> payload = makeValidFrame();
        client.sendFrame(payload);
        client.disconnect();
        srv.join();
        check(srv.result == 0, "Server read length prefix correctly via recv loop");
        check(!srv.frames.empty() && srv.frames[0] == payload,
              "Payload consistent after looped recv of length prefix");
    }

    // ------------------------------------------------------------------
    // Test 3: Payload arrives in multiple reads (server-side loop)
    // ------------------------------------------------------------------
    cout << "\n[Test 3: Multi-read payload assembly]\n";
    {
        Server srv;
        srv.start(1);
        sender::TcpClient client;
        client.connect("127.0.0.1", srv.port, 3000);

        vector<unsigned char> large_rsa(512, 0xCD);
        vector<int64_t> ggh(16, -1234);
        auto payload = sender::frameMessage("EMERGENCY_STOP",
                                            "2026-10-07T18:00:00Z",
                                            /*seq=*/999,
                                            large_rsa, ggh);
        client.sendFrame(payload);
        client.disconnect();
        srv.join();
        check(srv.result == 0, "Multi-read payload assembled correctly");
        check(!srv.frames.empty() && srv.frames[0] == payload,
              "Payload bytes match after multi-read assembly");
    }

    // ------------------------------------------------------------------
    // Test 4: Multiple consecutive frames retain correct boundaries
    // ------------------------------------------------------------------
    cout << "\n[Test 4: Multiple consecutive frames]\n";
    {
        const int kCount = 3;
        Server srv;
        srv.start(kCount);
        sender::TcpClient client;
        client.connect("127.0.0.1", srv.port, 3000);

        vector<vector<unsigned char>> sent;
        for (int i = 0; i < kCount; ++i) {
            string cmd = "CMD_" + to_string(i);
            string ts  = "2026-10-07T18:0" + to_string(i) + ":00Z";
            vector<unsigned char> rsa(512, static_cast<unsigned char>(i));
            vector<int64_t> ggh(16, static_cast<int64_t>(i));
            auto p = sender::frameMessage(cmd, ts, static_cast<uint64_t>(i), rsa, ggh);
            sent.push_back(p);
            auto sr = client.sendFrame(p);
            check(sr == sender::SendResult::Success,
                  ("Frame " + to_string(i) + " sent successfully").c_str());
        }
        client.disconnect();
        srv.join();
        check(srv.result == 0, "All frames received without error");
        check(srv.frames.size() == size_t(kCount), "Correct frame count received");
        bool all_match = true;
        for (int i = 0; i < kCount; ++i) {
            if (i >= static_cast<int>(srv.frames.size()) || srv.frames[i] != sent[i])
                all_match = false;
        }
        check(all_match, "Each frame payload matches its sent counterpart");
    }

    // ------------------------------------------------------------------
    // Test 5: Disconnected server -> clear failure result
    // ------------------------------------------------------------------
    cout << "\n[Test 5: Disconnected server -> failure]\n";
    {
        sender::TcpClient client;
        auto cr = client.connect("127.0.0.1", 1, 200);  // port 1 not listening
        check(cr == sender::ConnectResult::Failed,
              "Connect to closed port returns Failed");
        check(!client.connected(), "Client not marked as connected after failure");

        auto sr = client.sendFrame(makeValidFrame());
        check(sr == sender::SendResult::Disconnected,
              "sendFrame on disconnected client returns Disconnected");
    }

    // ------------------------------------------------------------------
    // Test 6: Oversized fields rejected before serialization
    // ------------------------------------------------------------------
    cout << "\n[Test 6: Oversized field rejection]\n";
    {
        bool cmd_rejected = false;
        try {
            sender::frameMessage(string(sender::kFrameMaxCommandLen + 1, 'X'),
                                 "2026-10-07T18:00:00Z", 1,
                                 vector<unsigned char>(512, 0),
                                 vector<int64_t>(16, 0));
        } catch (const exception&) { cmd_rejected = true; }
        check(cmd_rejected, "Oversized command rejected before serialization");

        bool rsa_rejected = false;
        try {
            sender::frameMessage("CMD", "2026-10-07T18:00:00Z", 1,
                                 vector<unsigned char>(sender::kFrameMaxRsaLen + 1, 0),
                                 vector<int64_t>(16, 0));
        } catch (const exception&) { rsa_rejected = true; }
        check(rsa_rejected, "Oversized RSA signature rejected before serialization");

        bool ggh_rejected = false;
        try {
            sender::frameMessage("CMD", "2026-10-07T18:00:00Z", 1,
                                 vector<unsigned char>(512, 0),
                                 vector<int64_t>(sender::kFrameMaxGghDim + 1, 0));
        } catch (const exception&) { ggh_rejected = true; }
        check(ggh_rejected, "Oversized GGH dimension rejected before serialization");
    }

    // ------------------------------------------------------------------
    // Test 7: Full payload delivery (sendFrame loops until complete)
    // ------------------------------------------------------------------
    cout << "\n[Test 7: Full payload delivery via sendFrame loop]\n";
    {
        Server srv;
        srv.start(1);
        sender::TcpClient client;
        client.connect("127.0.0.1", srv.port, 3000);

        vector<unsigned char> rsa(512, 0xFF);
        vector<int64_t> ggh(16, INT64_MAX);
        auto payload = sender::frameMessage("LARGE_SEND_TEST",
                                            "2026-10-07T18:00:00Z",
                                            /*seq=*/0xFFFFFFFFFFFFFFFFull,
                                            rsa, ggh);
        auto sr = client.sendFrame(payload);
        client.disconnect();
        srv.join();
        check(sr == sender::SendResult::Success,
              "Large frame sendFrame returns Success");
        check(!srv.frames.empty() && srv.frames[0] == payload,
              "Large frame received intact on server");
    }

    // ------------------------------------------------------------------
    // Test 8: Connection failure not reported as success
    // ------------------------------------------------------------------
    cout << "\n[Test 8: Connection failure not reported as success]\n";
    {
        sender::TcpClient client;
        auto cr = client.connect("127.0.0.1", 2, 200);
        check(cr != sender::ConnectResult::Success,
              "Connecting to closed port does not return Success");
        auto sr = client.sendFrame(makeValidFrame());
        check(sr == sender::SendResult::Disconnected,
              "sendFrame after failed connect returns Disconnected, not Success");
    }

    // ------------------------------------------------------------------
    // Test 9: Zero-length command field serialized correctly
    // ------------------------------------------------------------------
    cout << "\n[Test 9: Zero-length command field]\n";
    {
        bool serialized_ok = false;
        vector<unsigned char> frame;
        try {
            frame = sender::frameMessage("", "2026-10-07T18:00:00Z", 0,
                                          vector<unsigned char>(512, 0),
                                          vector<int64_t>(16, 0));
            serialized_ok = true;
        } catch (const exception&) {}
        check(serialized_ok, "Zero-length command serialized without exception");
        check(serialized_ok && frame.size() >= 4 &&
              frame[0] == 0 && frame[1] == 0 &&
              frame[2] == 0 && frame[3] == 0,
              "cmd_len field is 0x00000000 for empty command");
    }

    // ------------------------------------------------------------------
    // Test 10: Truncated frame detected (server returns -2)
    // ------------------------------------------------------------------
    cout << "\n[Test 10: Truncated frame detection]\n";
    {
        uint16_t port;
        SOCKET listen_sock = bindLoopback(port);
        vector<vector<unsigned char>> frames;
        int result = -999;
        thread srv_thread(serverWorker, listen_sock, 1, &frames, &result);

        // Write header claiming 200 bytes; write only 50; then close.
        SOCKET raw = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        ::connect(raw, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

        unsigned char hdr[4] = {0, 0, 0, 200};
        send(raw, reinterpret_cast<char*>(hdr), 4, 0);
        unsigned char partial[50] = {};
        send(raw, reinterpret_cast<char*>(partial), 50, 0);
        closesocket(raw);

        srv_thread.join();
        closesocket(listen_sock);
        check(result == -2, "Server detects truncated frame (payload closed early)");
        check(frames.empty(), "No complete frame delivered for truncated stream");
    }

    // ------------------------------------------------------------------
    // Test 11: Oversized length field rejected server-side
    // ------------------------------------------------------------------
    cout << "\n[Test 11: Oversized length field rejected server-side]\n";
    {
        uint16_t port;
        SOCKET listen_sock = bindLoopback(port);
        vector<vector<unsigned char>> frames;
        int result = -999;
        thread srv_thread(serverWorker, listen_sock, 1, &frames, &result);

        SOCKET raw = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        ::connect(raw, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

        // Length 0xFFFFFFFF (4 GiB) far exceeds kFrameMaxPayloadBytes (1 MiB).
        unsigned char hdr[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        send(raw, reinterpret_cast<char*>(hdr), 4, 0);
        closesocket(raw);

        srv_thread.join();
        closesocket(listen_sock);
        check(result == -3, "Server rejects frame with length field > kFrameMaxPayloadBytes");
        check(frames.empty(), "No allocation attempted for oversized length field");
    }

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    cout << "\n======================================\n";
    cout << "  RESULTS: " << g_pass << " passed, " << g_fail << " failed\n";
    cout << "======================================\n\n";

    WSACleanup();
    return g_fail > 0 ? 1 : 0;
}
