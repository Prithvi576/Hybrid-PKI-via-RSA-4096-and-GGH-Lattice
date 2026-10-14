#include "machine_manager.hpp"

#include <windows.h>
#include <openssl/rand.h>
#include <algorithm>
#include <iomanip>
#include <sstream>

using namespace std;

namespace sender {

namespace {
string nowUtcString() {
    SYSTEMTIME now{};
    GetSystemTime(&now);
    ostringstream out;
    out << setfill('0')
        << setw(4) << now.wYear << '-'
        << setw(2) << now.wMonth << '-'
        << setw(2) << now.wDay << 'T'
        << setw(2) << now.wHour << ':'
        << setw(2) << now.wMinute << ':'
        << setw(2) << now.wSecond << 'Z';
    return out.str();
}
}  // namespace

MachineManager::MachineManager(LocalStorage& storage) : storage_(storage) {
    machines_ = storage_.loadMachines();
}

string MachineManager::generateId() {
    unsigned char bytes[8];
    RAND_bytes(bytes, sizeof(bytes));
    ostringstream id;
    id << hex << setfill('0');
    for (auto b : bytes) id << setw(2) << static_cast<unsigned>(b);
    return id.str();
}

void MachineManager::persist() {
    storage_.saveMachines(machines_);
}

string MachineManager::addMachine(const string& name,
                                  const string& hostname,
                                  uint16_t port) {
    MachineRecord m;
    m.id = generateId();
    m.display_name = name;
    m.hostname = hostname;
    m.port = port;
    m.created_utc = nowUtcString();
    m.last_activity_utc = m.created_utc;
    machines_.push_back(move(m));
    persist();
    return machines_.back().id;
}

void MachineManager::updateMachine(const string& id,
                                   const string& name,
                                   const string& hostname,
                                   uint16_t port) {
    auto* m = findMachine(id);
    if (!m) return;
    m->display_name = name;
    m->hostname = hostname;
    m->port = port;
    persist();
}

void MachineManager::removeMachine(const string& id) {
    machines_.erase(
        remove_if(machines_.begin(), machines_.end(),
                  [&](const MachineRecord& m) { return m.id == id; }),
        machines_.end());
    keys_.erase(id);
    persist();
}

MachineRecord* MachineManager::findMachine(const string& id) {
    for (auto& m : machines_) {
        if (m.id == id) return &m;
    }
    return nullptr;
}

const MachineRecord* MachineManager::findMachine(const string& id) const {
    for (const auto& m : machines_) {
        if (m.id == id) return &m;
    }
    return nullptr;
}

MachineKeys& MachineManager::keysFor(const string& machine_id) {
    return keys_[machine_id];
}

void MachineManager::touchActivity(const string& machine_id) {
    auto* m = findMachine(machine_id);
    if (m) {
        m->last_activity_utc = nowUtcString();
        persist();
    }
}

}  // namespace sender
