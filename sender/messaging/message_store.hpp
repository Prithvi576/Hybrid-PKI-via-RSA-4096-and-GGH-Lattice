#ifndef SENDER_MESSAGE_STORE_HPP
#define SENDER_MESSAGE_STORE_HPP

#include "../models/message_model.hpp"
#include "../storage/local_storage.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace sender {

class MessageStore {
public:
    explicit MessageStore(LocalStorage& storage);

    void addMessage(const MessageRecord& msg);
    void updateMessageStatus(const std::string& machine_id,
                             const std::string& message_id,
                             SendStatus status);
    const std::vector<MessageRecord>& messagesFor(const std::string& machine_id);
    std::string lastCommandPreview(const std::string& machine_id);

private:
    LocalStorage& storage_;
    std::unordered_map<std::string, std::vector<MessageRecord>> cache_;

    void ensureLoaded(const std::string& machine_id);
};

}  // namespace sender

#endif
