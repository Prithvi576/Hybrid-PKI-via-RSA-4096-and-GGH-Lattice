#include "message_store.hpp"

using namespace std;

namespace sender {

MessageStore::MessageStore(LocalStorage& storage) : storage_(storage) {}

void MessageStore::ensureLoaded(const string& machine_id) {
    if (cache_.find(machine_id) == cache_.end()) {
        cache_[machine_id] = storage_.loadMessages(machine_id);
    }
}

void MessageStore::addMessage(const MessageRecord& msg) {
    ensureLoaded(msg.machine_id);
    cache_[msg.machine_id].push_back(msg);
    storage_.saveMessages(msg.machine_id, cache_[msg.machine_id]);
}

void MessageStore::updateMessageStatus(const string& machine_id,
                                       const string& message_id,
                                       SendStatus status) {
    ensureLoaded(machine_id);
    auto& msgs = cache_[machine_id];
    for (auto& m : msgs) {
        if (m.id == message_id) {
            m.status = status;
            break;
        }
    }
    storage_.saveMessages(machine_id, msgs);
}

const vector<MessageRecord>& MessageStore::messagesFor(const string& machine_id) {
    ensureLoaded(machine_id);
    return cache_[machine_id];
}

string MessageStore::lastCommandPreview(const string& machine_id) {
    ensureLoaded(machine_id);
    const auto& msgs = cache_[machine_id];
    if (msgs.empty()) return "";
    const auto& last = msgs.back();
    if (last.command.size() <= 30) return last.command;
    return last.command.substr(0, 27) + "...";
}

}  // namespace sender
