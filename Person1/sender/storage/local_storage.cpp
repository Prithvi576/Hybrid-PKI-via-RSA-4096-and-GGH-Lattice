#include "local_storage.hpp"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>

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
    pos = json.find('"', pos + search.size());
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
                case 'b':  result += '\b'; break;
                case 'f':  result += '\f'; break;
                default: result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }
        ++pos;
    }
    return result;
}

uint64_t extractJsonUint(const string& json, const string& key) {
    string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == string::npos) return 0;
    pos = json.find(':', pos + search.size());
    if (pos == string::npos) return 0;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    string num;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        num += json[pos++];
    }
    return num.empty() ? 0 : stoull(num);
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

vector<string> splitJsonArray(const string& json) {
    vector<string> items;
    int depth = 0;
    size_t start = string::npos;
    for (size_t i = 0; i < json.size(); ++i) {
        if (json[i] == '{') {
            if (depth == 0) start = i;
            ++depth;
        } else if (json[i] == '}') {
            --depth;
            if (depth == 0 && start != string::npos) {
                items.push_back(json.substr(start, i - start + 1));
                start = string::npos;
            }
        }
    }
    return items;
}

string readFile(const string& path) {
    ifstream file(path, ios::binary);
    if (!file) return "";
    ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

void writeFile(const string& path, const string& content) {
    ofstream file(path, ios::binary | ios::trunc);
    if (!file) throw runtime_error("Cannot write: " + path);
    file << content;
}

}  // namespace

LocalStorage::LocalStorage(const string& base_directory) : base_dir_(base_directory) {
    ensureDirectory(base_dir_);
    ensureDirectory(base_dir_ + "\\messages");
}

void LocalStorage::ensureDirectory(const string& path) {
    CreateDirectoryA(path.c_str(), nullptr);
}

string LocalStorage::machineMessagesPath(const string& machine_id) {
    return base_dir_ + "\\messages\\" + machine_id + ".json";
}

void LocalStorage::saveMachines(const vector<MachineRecord>& machines) {
    ostringstream json;
    json << "[\n";
    for (size_t i = 0; i < machines.size(); ++i) {
        const auto& m = machines[i];
        json << "  {\n"
             << "    \"id\": \"" << escapeJson(m.id) << "\",\n"
             << "    \"display_name\": \"" << escapeJson(m.display_name) << "\",\n"
             << "    \"hostname\": \"" << escapeJson(m.hostname) << "\",\n"
             << "    \"port\": " << m.port << ",\n"
             << "    \"created_utc\": \"" << escapeJson(m.created_utc) << "\",\n"
             << "    \"last_activity_utc\": \"" << escapeJson(m.last_activity_utc) << "\"\n"
             << "  }";
        if (i + 1 < machines.size()) json << ",";
        json << "\n";
    }
    json << "]\n";
    writeFile(base_dir_ + "\\machines.json", json.str());
}

vector<MachineRecord> LocalStorage::loadMachines() {
    string content = readFile(base_dir_ + "\\machines.json");
    if (content.empty()) return {};

    vector<MachineRecord> machines;
    auto items = splitJsonArray(content);
    for (const auto& item : items) {
        MachineRecord m;
        m.id = extractJsonString(item, "id");
        m.display_name = extractJsonString(item, "display_name");
        m.hostname = extractJsonString(item, "hostname");
        m.port = static_cast<uint16_t>(extractJsonUint(item, "port"));
        m.created_utc = extractJsonString(item, "created_utc");
        m.last_activity_utc = extractJsonString(item, "last_activity_utc");
        if (!m.id.empty()) machines.push_back(move(m));
    }
    return machines;
}

void LocalStorage::saveMessages(const string& machine_id,
                                const vector<MessageRecord>& messages) {
    ostringstream json;
    json << "[\n";
    for (size_t i = 0; i < messages.size(); ++i) {
        const auto& msg = messages[i];
        json << "  {\n"
             << "    \"id\": \"" << escapeJson(msg.id) << "\",\n"
             << "    \"machine_id\": \"" << escapeJson(msg.machine_id) << "\",\n"
             << "    \"command\": \"" << escapeJson(msg.command) << "\",\n"
             << "    \"timestamp_utc\": \"" << escapeJson(msg.timestamp_utc) << "\",\n"
             << "    \"sequence\": " << msg.sequence << ",\n"
             << "    \"rsa_fingerprint\": \"" << escapeJson(msg.rsa_fingerprint) << "\",\n"
             << "    \"ggh_fingerprint\": \"" << escapeJson(msg.ggh_fingerprint) << "\",\n"
             << "    \"rsa_signature_size\": " << msg.rsa_signature_size << ",\n"
             << "    \"ggh_signature_size\": " << msg.ggh_signature_size << ",\n"
             << "    \"status\": " << static_cast<int>(msg.status) << ",\n"
             << "    \"is_outgoing\": " << (msg.is_outgoing ? "true" : "false") << "\n"
             << "  }";
        if (i + 1 < messages.size()) json << ",";
        json << "\n";
    }
    json << "]\n";
    writeFile(machineMessagesPath(machine_id), json.str());
}

vector<MessageRecord> LocalStorage::loadMessages(const string& machine_id) {
    string content = readFile(machineMessagesPath(machine_id));
    if (content.empty()) return {};

    vector<MessageRecord> messages;
    auto items = splitJsonArray(content);
    for (const auto& item : items) {
        MessageRecord msg;
        msg.id = extractJsonString(item, "id");
        msg.machine_id = extractJsonString(item, "machine_id");
        msg.command = extractJsonString(item, "command");
        msg.timestamp_utc = extractJsonString(item, "timestamp_utc");
        msg.sequence = extractJsonUint(item, "sequence");
        msg.rsa_fingerprint = extractJsonString(item, "rsa_fingerprint");
        msg.ggh_fingerprint = extractJsonString(item, "ggh_fingerprint");
        msg.rsa_signature_size = static_cast<size_t>(extractJsonUint(item, "rsa_signature_size"));
        msg.ggh_signature_size = static_cast<size_t>(extractJsonUint(item, "ggh_signature_size"));
        msg.status = static_cast<SendStatus>(extractJsonInt(item, "status"));
        string outgoing_str = extractJsonString(item, "is_outgoing");
        msg.is_outgoing = (item.find("\"is_outgoing\": true") != string::npos ||
                           item.find("\"is_outgoing\":true") != string::npos);
        if (!msg.id.empty()) messages.push_back(move(msg));
    }
    return messages;
}

void LocalStorage::saveSequence(uint64_t sequence) {
    writeFile(base_dir_ + "\\sequence.dat", to_string(sequence));
}

uint64_t LocalStorage::loadSequence() {
    string content = readFile(base_dir_ + "\\sequence.dat");
    if (content.empty()) return 1;
    try { return stoull(content); } catch (...) { return 1; }
}

}  // namespace sender
