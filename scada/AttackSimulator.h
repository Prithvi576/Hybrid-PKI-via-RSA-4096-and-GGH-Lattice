
#ifndef ATTACK_SIMULATOR_H
#define ATTACK_SIMULATOR_H

#include <string>

struct AttackResult {
    std::string attackType;
    bool detected = false;
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

#endif
