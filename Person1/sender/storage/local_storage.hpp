#ifndef SENDER_LOCAL_STORAGE_HPP
#define SENDER_LOCAL_STORAGE_HPP

#include "../models/machine_model.hpp"
#include "../models/message_model.hpp"

#include <string>
#include <vector>

namespace sender {

class LocalStorage {
public:
    explicit LocalStorage(const std::string& base_directory);

    void saveMachines(const std::vector<MachineRecord>& machines);
    std::vector<MachineRecord> loadMachines();

    void saveMessages(const std::string& machine_id,
                      const std::vector<MessageRecord>& messages);
    std::vector<MessageRecord> loadMessages(const std::string& machine_id);

    void saveSequence(uint64_t sequence);
    uint64_t loadSequence();

private:
    std::string base_dir_;
    void ensureDirectory(const std::string& path);
    std::string machineMessagesPath(const std::string& machine_id);
};

}  // namespace sender

#endif
