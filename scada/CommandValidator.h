#pragma once

#include <cstdint>
#include <string>

#include "RBAC.h"
#include "ReplayProtection.h"

struct SCADACommand {
    std::string userId;
    std::string role;
    std::string command;

    std::uint64_t timestamp;
    std::uint64_t sequence;
};

class CommandValidator {
public:
    CommandValidator(
        RBAC& rbac,
        ReplayProtection& replayProtection
    );

    bool validate(
        const SCADACommand& command,
        std::uint64_t currentTime
    );

private:
    RBAC& rbac;
    ReplayProtection& replayProtection;
};