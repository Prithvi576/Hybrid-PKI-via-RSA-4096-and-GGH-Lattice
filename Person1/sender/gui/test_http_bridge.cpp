#include <iostream>
#include <cassert>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "http_bridge.hpp"
#include "../storage/local_storage.hpp"
#include "../machines/machine_manager.hpp"
#include "../messaging/message_store.hpp"

using namespace std;

static string httpGet(uint16_t port, const string& path) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "";
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons(port);
    if (connect(s, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) != 0) {
        closesocket(s);
        return "";
    }
    string req = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    send(s, req.data(), static_cast<int>(req.size()), 0);
    char buf[4096];
    string resp;
    int r;
    while ((r = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[r] = '\0';
        resp += buf;
    }
    closesocket(s);
    return resp;
}

static string httpPost(uint16_t port, const string& path, const string& json) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "";
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons(port);
    if (connect(s, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) != 0) {
        closesocket(s);
        return "";
    }
    string req = "POST " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                 "Content-Length: " + to_string(json.size()) + "\r\nConnection: close\r\n\r\n" + json;
    send(s, req.data(), static_cast<int>(req.size()), 0);
    char buf[4096];
    string resp;
    int r;
    while ((r = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[r] = '\0';
        resp += buf;
    }
    closesocket(s);
    return resp;
}

int main() {
    cout << "=== Running test_http_bridge ===" << endl;

    string tempStorage = "test_sender_data";
    sender::LocalStorage storage(tempStorage);
    sender::MachineManager machines(storage);
    sender::MessageStore messages(storage);

    string machId = machines.addMachine("Test Unit", "127.0.0.1", 5020);

    sender::HttpBridge bridge(storage, machines, messages, "Person1/sender/ui", 0);
    if (!bridge.start()) {
        cerr << "FAIL: Could not start HttpBridge on localhost" << endl;
        return 1;
    }

    uint16_t port = bridge.port();
    cout << "HttpBridge listening on port " << port << endl;

    // Test 1: GET /api/status
    {
        string resp = httpGet(port, "/api/status");
        if (resp.find("200 OK") == string::npos || resp.find("Hawk PKI SCADA Sender") == string::npos) {
            cerr << "FAIL: /api/status returned invalid response: " << resp << endl;
            return 1;
        }
        cout << "[PASS] /api/status OK" << endl;
    }

    // Test 2: GET /api/machines
    {
        string resp = httpGet(port, "/api/machines");
        if (resp.find("200 OK") == string::npos || resp.find("Test Unit") == string::npos) {
            cerr << "FAIL: /api/machines returned invalid response: " << resp << endl;
            return 1;
        }
        cout << "[PASS] /api/machines lists created machines" << endl;
    }

    // Test 3: POST /api/keys/generate RSA
    {
        string body = "{\"machine_id\":\"" + machId + "\",\"type\":\"rsa\"}";
        string resp = httpPost(port, "/api/keys/generate", body);
        if (resp.find("200 OK") == string::npos || resp.find("\"success\":true") == string::npos || resp.find("\"size_bytes\":512") == string::npos) {
            cerr << "FAIL: RSA keygen API failed: " << resp << endl;
            return 1;
        }
        cout << "[PASS] RSA-4096 key generated successfully via C++ backend" << endl;
    }

    // Test 4: POST /api/keys/generate GGH
    {
        string body = "{\"machine_id\":\"" + machId + "\",\"type\":\"ggh\"}";
        string resp = httpPost(port, "/api/keys/generate", body);
        if (resp.find("200 OK") == string::npos || resp.find("\"success\":true") == string::npos || resp.find("\"dimension\":16") == string::npos) {
            cerr << "FAIL: GGH keygen API failed: " << resp << endl;
            return 1;
        }
        cout << "[PASS] GGH lattice key generated successfully via C++ backend" << endl;
    }

    // Test 5: GET /api/keys
    {
        string resp = httpGet(port, "/api/keys?machine_id=" + machId);
        if (resp.find("200 OK") == string::npos || resp.find("\"ready\":true") == string::npos) {
            cerr << "FAIL: Keys ready status check failed: " << resp << endl;
            return 1;
        }
        cout << "[PASS] /api/keys reports both RSA and GGH ready" << endl;
    }

    // Test 6: POST /api/send (hybrid signing and TCP frame attempt)
    {
        string body = "{\"machine_id\":\"" + machId + "\",\"command\":\"SET_VALVE_4_OPEN\"}";
        string resp = httpPost(port, "/api/send", body);
        // Signing should succeed and TCP will return ConnectionFailed because port 5020 is not listening
        if (resp.find("200 OK") == string::npos || resp.find("rsa_signature_size\":512") == string::npos || resp.find("ggh_signature_size\":128") == string::npos) {
            cerr << "FAIL: /api/send hybrid signing failed: " << resp << endl;
            return 1;
        }
        cout << "[PASS] /api/send invoked hybridSign (RSA:512B, GGH:128B) and framed payload" << endl;
    }

    // Test 7: GET /api/messages
    {
        string resp = httpGet(port, "/api/messages?machine_id=" + machId);
        if (resp.find("200 OK") == string::npos || resp.find("SET_VALVE_4_OPEN") == string::npos) {
            cerr << "FAIL: Message history did not persist command: " << resp << endl;
            return 1;
        }
        cout << "[PASS] /api/messages returned persistent message history" << endl;
    }

    bridge.stop();
    cout << "=== All test_http_bridge tests passed successfully! ===" << endl;
    return 0;
}
