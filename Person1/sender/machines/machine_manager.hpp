#ifndef SENDER_MACHINE_MANAGER_HPP
#define SENDER_MACHINE_MANAGER_HPP

#include <windows.h>
#include "../models/machine_model.hpp"
#include "../storage/local_storage.hpp"
#include "crypto_api.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace sender {

struct MachineKeys {
    std::unique_ptr<hybrid_pki::RSAKeyPair> rsa;
    std::unique_ptr<hybrid_pki::GGHKeyPair> ggh;
};

class MachineManager {
public:
    explicit MachineManager(LocalStorage& storage);

    const std::vector<MachineRecord>& machines() const { return machines_; }

    std::string addMachine(const std::string& name,
                           const std::string& hostname,
                           uint16_t port);
    void updateMachine(const std::string& id,
                       const std::string& name,
                       const std::string& hostname,
                       uint16_t port);
    void removeMachine(const std::string& id);
    MachineRecord* findMachine(const std::string& id);
    const MachineRecord* findMachine(const std::string& id) const;

    MachineKeys& keysFor(const std::string& machine_id);
    void touchActivity(const std::string& machine_id);

private:
    LocalStorage& storage_;
    std::vector<MachineRecord> machines_;
    std::unordered_map<std::string, MachineKeys> keys_;

    std::string generateId();
    void persist();
};

}  // namespace sender

#endif
