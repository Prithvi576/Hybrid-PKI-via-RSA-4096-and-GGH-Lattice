#ifndef SENDER_MACHINE_MODEL_HPP
#define SENDER_MACHINE_MODEL_HPP

#include <cstdint>
#include <string>

struct MachineRecord {
    std::string id;
    std::string display_name;
    std::string hostname;
    uint16_t port{502};
    std::string created_utc;
    std::string last_activity_utc;
};

#endif
