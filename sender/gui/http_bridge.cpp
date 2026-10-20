#include "http_bridge.hpp"

#include <windows.h>
#include <openssl/rand.h>

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace std;

namespace sender {

namespace {

string escapeJson(const string& s) {
    string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

string extractJsonString(const string& json, const string& key) {
    string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == string::npos) return "";
    pos = json.find('"', pos);
    if (pos == string::npos) return "";
    ++pos;
    string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            ++pos;
            switch (json[pos]) {
                case '"':  result += '"'; break;
                case '\\': result += '\\'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                default:   result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }
        ++pos;
    }
    return result;
}

int extractJsonInt(const string& json, const string& key) {
    string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == string::npos) return 0;
    pos = json.find(':', pos + search.size());
    if (pos == string::npos) return 0;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    string num;
    if (pos < json.size() && json[pos] == '-') num += json[pos++];
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        num += json[pos++];
    }
    return num.empty() ? 0 : stoi(num);
}

string getQueryParam(const string& raw_path, const string& key) {
    auto qpos = raw_path.find('?');
    if (qpos == string::npos) return "";
    string query = raw_path.substr(qpos + 1);
    string search = key + "=";
    auto pos = query.find(search);
    if (pos == string::npos) return "";
    pos += search.size();
    auto end_pos = query.find('&', pos);
    return query.substr(pos, end_pos == string::npos ? string::npos : end_pos - pos);
}

string nowIso8601Utc() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    ostringstream oss;
    oss << setfill('0')
        << setw(4) << st.wYear << '-'
        << setw(2) << st.wMonth << '-'
        << setw(2) << st.wDay << 'T'
        << setw(2) << st.wHour << ':'
        << setw(2) << st.wMinute << ':'
        << setw(2) << st.wSecond << 'Z';
    return oss.str();
}

string generateRandomMsgId() {
    unsigned char bytes[6];
    RAND_bytes(bytes, sizeof(bytes));
    ostringstream id;
    id << "msg_" << hex << setfill('0');
    for (auto b : bytes) id << setw(2) << static_cast<unsigned>(b);
    return id.str();
}

string readFileBinary(const string& filepath) {
    ifstream in(filepath, ios::binary);
    if (!in.is_open()) return "";
    ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

}  // namespace

HttpBridge::HttpBridge(LocalStorage& storage,
                       MachineManager& machines,
                       MessageStore& messages,
                       const string& assets_dir,
                       uint16_t port)
    : storage_(storage),
      machines_(machines),
      messages_(messages),
      assets_dir_(assets_dir),
      port_(port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

HttpBridge::~HttpBridge() {
    stop();
    WSACleanup();
}

string HttpBridge::rootUrl() const {
    return "http://127.0.0.1:" + to_string(port_) + "/";
}

bool HttpBridge::start() {
    if (running_) return true;

    listen_sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock_ == INVALID_SOCKET) return false;

    // Allow address reuse
    int opt = 1;
    setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Try starting on requested port; if 0 or fails, try nearby ports
    uint16_t try_port = port_ ? port_ : 18443;
    bool bound = false;
    for (int i = 0; i < 20; ++i) {
        sin.sin_port = htons(try_port + i);
        if (::bind(listen_sock_, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == 0) {
            port_ = try_port + i;
            bound = true;
            break;
        }
    }

    if (!bound) {
        closesocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET;
        return false;
    }

    if (listen(listen_sock_, 16) != 0) {
        closesocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET;
        return false;
    }

    running_ = true;
    thread_ = make_unique<std::thread>(&HttpBridge::listenLoop, this);
    return true;
}

void HttpBridge::stop() {
    if (!running_) return;
    running_ = false;
    if (listen_sock_ != INVALID_SOCKET) {
        closesocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET;
    }
    if (thread_ && thread_->joinable()) {
        thread_->join();
        thread_.reset();
    }
}

void HttpBridge::listenLoop() {
    while (running_) {
        sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);
        SOCKET s = accept(listen_sock_, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (s == INVALID_SOCKET) {
            if (!running_) break;
            continue;
        }

        // Spawn client handler in thread to not block listening
        std::thread([this, s]() {
            handleClient(s);
        }).detach();
    }
}

void HttpBridge::handleClient(SOCKET client_sock) {
    char buf[8192];
    int recvd = recv(client_sock, buf, sizeof(buf) - 1, 0);
    if (recvd <= 0) {
        closesocket(client_sock);
        return;
    }
    buf[recvd] = '\0';
    string req(buf, recvd);

    // Parse request line: METHOD PATH HTTP/1.1
    istringstream req_stream(req);
    string method, raw_path, proto;
    req_stream >> method >> raw_path >> proto;

    // Find end of headers (\r\n\r\n)
    auto body_pos = req.find("\r\n\r\n");
    string body;
    if (body_pos != string::npos) {
        body = req.substr(body_pos + 4);
    }

    string status_code = "200 OK";
    string content_type = "application/json";
    string response_body;

    handleRequest(method, raw_path, body, status_code, content_type, response_body);

    ostringstream resp;
    resp << "HTTP/1.1 " << status_code << "\r\n"
         << "Content-Type: " << content_type << "\r\n"
         << "Content-Length: " << response_body.size() << "\r\n"
         << "Cache-Control: no-cache, no-store, must-revalidate\r\n"
         << "Pragma: no-cache\r\n"
         << "Expires: 0\r\n"
         << "Access-Control-Allow-Origin: *\r\n"
         << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
         << "Access-Control-Allow-Headers: Content-Type\r\n"
         << "Connection: close\r\n\r\n"
         << response_body;

    string resp_str = resp.str();
    send(client_sock, resp_str.data(), static_cast<int>(resp_str.size()), 0);
    closesocket(client_sock);
}

void HttpBridge::handleRequest(const string& method,
                              const string& raw_path,
                              const string& body,
                              string& status_code,
                              string& content_type,
                              string& response_body) {
    if (method == "OPTIONS") {
        status_code = "204 No Content";
        content_type = "text/plain";
        response_body = "";
        return;
    }

    string path = raw_path;
    auto qpos = path.find('?');
    if (qpos != string::npos) {
        path = path.substr(0, qpos);
    }

    // 1. API Endpoints
    if (path == "/api/status") {
        uint64_t seq = storage_.loadSequence();
        response_body = "{\"status\":\"ok\",\"app\":\"Hawk PKI SCADA Sender\",\"version\":\"1.0\",\"sequence\":" +
                        to_string(seq) + "}";
        return;
    }

    if (path == "/api/machines") {
        if (method == "GET") {
            const auto& list = machines_.machines();
            ostringstream oss;
            oss << "[";
            for (size_t i = 0; i < list.size(); ++i) {
                const auto& m = list[i];
                if (i > 0) oss << ",";
                oss << "{\"id\":\"" << escapeJson(m.id) << "\","
                    << "\"name\":\"" << escapeJson(m.display_name) << "\","
                    << "\"display_name\":\"" << escapeJson(m.display_name) << "\","
                    << "\"host\":\"" << escapeJson(m.hostname) << "\","
                    << "\"hostname\":\"" << escapeJson(m.hostname) << "\","
                    << "\"port\":" << m.port << ","
                    << "\"created_utc\":\"" << escapeJson(m.created_utc) << "\","
                    << "\"last_activity_utc\":\"" << escapeJson(m.last_activity_utc) << "\"}";
            }
            oss << "]";
            response_body = oss.str();
            return;
        }

        if (method == "POST") {
            string action = extractJsonString(body, "action");
            if (action == "delete") {
                string id = extractJsonString(body, "id");
                machines_.removeMachine(id);
                response_body = "{\"success\":true}";
                return;
            }
            if (action == "update") {
                string id = extractJsonString(body, "id");
                string name = extractJsonString(body, "name");
                string host = extractJsonString(body, "host");
                int port = extractJsonInt(body, "port");
                machines_.updateMachine(id, name, host, static_cast<uint16_t>(port));
                response_body = "{\"success\":true}";
                return;
            }
            // default is "add"
            string name = extractJsonString(body, "name");
            string host = extractJsonString(body, "host");
            int port = extractJsonInt(body, "port");
            string id = machines_.addMachine(name, host, static_cast<uint16_t>(port ? port : 502));
            response_body = "{\"success\":true,\"id\":\"" + escapeJson(id) + "\"}";
            return;
        }
    }

    if (path == "/api/keys") {
        string machId = getQueryParam(raw_path, "machine_id");
        if (machId.empty()) {
            status_code = "400 Bad Request";
            response_body = "{\"error\":\"Missing machine_id\"}";
            return;
        }
        auto& k = machines_.keysFor(machId);
        bool rsaReady = (k.rsa != nullptr);
        bool gghReady = (k.ggh != nullptr);
        string rsaFp = rsaReady ? k.rsa->public_fingerprint : "";
        string gghFp = gghReady ? k.ggh->public_fingerprint : "";

        ostringstream oss;
        oss << "{\"rsa\":{\"ready\":" << (rsaReady ? "true" : "false")
            << ",\"fingerprint\":\"" << escapeJson(rsaFp)
            << "\",\"size_bytes\":" << (rsaReady ? 512 : 0) << "},"
            << "\"ggh\":{\"ready\":" << (gghReady ? "true" : "false")
            << ",\"fingerprint\":\"" << escapeJson(gghFp)
            << "\",\"dimension\":16,\"size_bytes\":" << (gghReady ? 128 : 0) << "}}";
        response_body = oss.str();
        return;
    }

    if (path == "/api/keys/generate" && method == "POST") {
        string machId = extractJsonString(body, "machine_id");
        string type = extractJsonString(body, "type");
        if (machId.empty()) {
            status_code = "400 Bad Request";
            response_body = "{\"error\":\"Missing machine_id\"}";
            return;
        }
        auto& k = machines_.keysFor(machId);
        if (type == "rsa") {
            try {
                k.rsa = make_unique<hybrid_pki::RSAKeyPair>(hybrid_pki::generateRSAKeyPair());
                response_body = "{\"success\":true,\"type\":\"rsa\",\"fingerprint\":\"" +
                                escapeJson(k.rsa->public_fingerprint) + "\",\"size_bytes\":512}";
            } catch (const exception& e) {
                status_code = "500 Internal Server Error";
                response_body = "{\"success\":false,\"error\":\"" + escapeJson(e.what()) + "\"}";
            }
            return;
        }
        if (type == "ggh") {
            try {
                k.ggh = make_unique<hybrid_pki::GGHKeyPair>(hybrid_pki::generateGGHKeyPair());
                response_body = "{\"success\":true,\"type\":\"ggh\",\"fingerprint\":\"" +
                                escapeJson(k.ggh->public_fingerprint) + "\",\"dimension\":16,\"size_bytes\":128}";
            } catch (const exception& e) {
                status_code = "500 Internal Server Error";
                response_body = "{\"success\":false,\"error\":\"" + escapeJson(e.what()) + "\"}";
            }
            return;
        }
        status_code = "400 Bad Request";
        response_body = "{\"error\":\"Invalid key type; expected rsa or ggh\"}";
        return;
    }

    if (path == "/api/messages") {
        string machId = getQueryParam(raw_path, "machine_id");
        if (machId.empty()) {
            status_code = "400 Bad Request";
            response_body = "{\"error\":\"Missing machine_id\"}";
            return;
        }
        const auto& msgs = messages_.messagesFor(machId);
        ostringstream oss;
        oss << "[";
        for (size_t i = 0; i < msgs.size(); ++i) {
            const auto& m = msgs[i];
            if (i > 0) oss << ",";
            string stStr = (m.status == SendStatus::SentToTcp) ? "SentToTcp"
                         : (m.status == SendStatus::ConnectionFailed) ? "ConnectionFailed"
                         : (m.status == SendStatus::Sending) ? "Sending"
                         : "NotSent";
            oss << "{\"id\":\"" << escapeJson(m.id) << "\","
                << "\"machine_id\":\"" << escapeJson(m.machine_id) << "\","
                << "\"command\":\"" << escapeJson(m.command) << "\","
                << "\"timestamp_utc\":\"" << escapeJson(m.timestamp_utc) << "\","
                << "\"sequence\":" << m.sequence << ","
                << "\"rsa_fingerprint\":\"" << escapeJson(m.rsa_fingerprint) << "\","
                << "\"ggh_fingerprint\":\"" << escapeJson(m.ggh_fingerprint) << "\","
                << "\"rsa_signature_size\":" << m.rsa_signature_size << ","
                << "\"ggh_signature_size\":" << m.ggh_signature_size << ","
                << "\"status\":\"" << stStr << "\"}";
        }
        oss << "]";
        response_body = oss.str();
        return;
    }

    if (path == "/api/send" && method == "POST") {
        string machId = extractJsonString(body, "machine_id");
        string cmd = extractJsonString(body, "command");

        if (cmd.empty()) {
            status_code = "400 Bad Request";
            response_body = "{\"success\":false,\"error\":\"Command text cannot be empty.\"}";
            return;
        }
        if (cmd.size() > 4096) {
            status_code = "400 Bad Request";
            response_body = "{\"success\":false,\"error\":\"Command exceeds maximum length of 4096 bytes.\"}";
            return;
        }
        const auto* m = machines_.findMachine(machId);
        if (!m) {
            status_code = "404 Not Found";
            response_body = "{\"success\":false,\"error\":\"Target machine not found.\"}";
            return;
        }
        auto& k = machines_.keysFor(machId);
        if (!k.rsa || !k.ggh) {
            status_code = "400 Bad Request";
            response_body = "{\"success\":false,\"error\":\"Both RSA-4096 and GGH keys must be generated before signing.\"}";
            return;
        }

        try {
            uint64_t seq = storage_.loadSequence();
            string ts = nowIso8601Utc();
            hybrid_pki::CommandEnvelope envelope{cmd, ts, seq};

            // Real hybrid signing
            auto signResult = hybrid_pki::hybridSign(envelope, *k.rsa, *k.ggh);
            storage_.saveSequence(seq + 1);

            // TCP frame
            auto frame = sender::frameMessage(
                cmd,
                envelope.timestamp_utc,
                envelope.sequence,
                signResult.signed_command.rsa_signature,
                signResult.signed_command.ggh_signature.lattice_point);

            // Async/direct TCP send to configured machine host & port
            sender::TcpClient client;
            sender::SendResult sendRes = sender::SendResult::Failed;
            auto connRes = client.connect(m->hostname, m->port, 3000);
            if (connRes == sender::ConnectResult::Success) {
                sendRes = client.sendFrame(frame);
            }

            // Save message record to persistent storage
            MessageRecord msg;
            msg.id = generateRandomMsgId();
            msg.machine_id = machId;
            msg.command = cmd;
            msg.timestamp_utc = envelope.timestamp_utc;
            msg.sequence = envelope.sequence;
            msg.rsa_fingerprint = k.rsa->public_fingerprint;
            msg.ggh_fingerprint = k.ggh->public_fingerprint;
            msg.rsa_signature_size = signResult.signed_command.rsa_signature.size();
            msg.ggh_signature_size = hybrid_pki::gghSignatureSize(signResult.signed_command.ggh_signature);
            msg.status = (sendRes == sender::SendResult::Success) ? SendStatus::SentToTcp : SendStatus::ConnectionFailed;
            msg.is_outgoing = true;

            messages_.addMessage(msg);
            machines_.touchActivity(machId);

            string stStr = (sendRes == sender::SendResult::Success) ? "SentToTcp" : "ConnectionFailed";
            ostringstream oss;
            oss << "{\"success\":" << (sendRes == sender::SendResult::Success ? "true" : "false")
                << ",\"status\":\"" << stStr << "\","
                << "\"sequence\":" << seq << ","
                << "\"rsa_signature_size\":" << msg.rsa_signature_size << ","
                << "\"ggh_signature_size\":" << msg.ggh_signature_size << "}";
            response_body = oss.str();
            return;
        } catch (const exception& e) {
            status_code = "500 Internal Server Error";
            response_body = "{\"success\":false,\"error\":\"" + escapeJson(e.what()) + "\"}";
            return;
        }
    }

    // 2. Static Files
    string filename = (path == "/" || path.empty()) ? "index.html" : path.substr(1);
    string fullpath = assets_dir_ + "\\" + filename;
    string file_bytes = readFileBinary(fullpath);

    // Fallback search locations if assets_dir_ was relative or different
    if (file_bytes.empty()) {
        file_bytes = readFileBinary("sender\\ui\\" + filename);
    }
    if (file_bytes.empty()) {
        file_bytes = readFileBinary("..\\sender\\ui\\" + filename);
    }

    if (file_bytes.empty()) {
        status_code = "404 Not Found";
        content_type = "text/plain";
        response_body = "File not found: " + filename;
        return;
    }

    if (filename.find(".html") != string::npos) content_type = "text/html; charset=utf-8";
    else if (filename.find(".css") != string::npos) content_type = "text/css; charset=utf-8";
    else if (filename.find(".js") != string::npos) content_type = "application/javascript; charset=utf-8";
    else if (filename.find(".svg") != string::npos) content_type = "image/svg+xml";
    else if (filename.find(".png") != string::npos) content_type = "image/png";
    else content_type = "application/octet-stream";

    response_body = std::move(file_bytes);
}

}  // namespace sender
