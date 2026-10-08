#pragma once

#include <string>

struct AttackResult {
    std::string attackType;
    bool detected;
    std::string message;
};

class AttackSimulator {
public:
    AttackResult simulateUnauthorizedRole(
        const std::string& role,
        const std::string& command
    );

    AttackResult simulateReplayAttack();

    AttackResult simulateModifiedCommand();

    AttackResult simulateInvalidCertificate();

    AttackResult simulateExpiredCertificate();
};