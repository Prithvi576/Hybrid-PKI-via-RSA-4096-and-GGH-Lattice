#include "AttackSimulator.h"

AttackResult AttackSimulator::simulateUnauthorizedRole(
    const std::string& role,
    const std::string& command)
{
    AttackResult result;

    result.attackType = "Unauthorized Role";

    // The actual RBAC system will reject the command.
    result.detected = true;

    result.message =
        "Unauthorized role '" + role +
        "' attempted command '" + command + "'";

    return result;
}


AttackResult AttackSimulator::simulateReplayAttack()
{
    AttackResult result;

    result.attackType = "Replay Attack";
    result.detected = true;

    result.message =
        "Previously processed command was replayed";

    return result;
}


AttackResult AttackSimulator::simulateModifiedCommand()
{
    AttackResult result;

    result.attackType = "Modified Command";

    // Actual RSA/GGH verification will detect this
    // when Person 1's cryptographic module is integrated.
    result.detected = true;

    result.message =
        "Command contents were modified after signing";

    return result;
}


AttackResult AttackSimulator::simulateInvalidCertificate()
{
    AttackResult result;

    result.attackType = "Invalid Certificate";
    result.detected = true;

    result.message =
        "Command received with an invalid certificate";

    return result;
}


AttackResult AttackSimulator::simulateExpiredCertificate()
{
    AttackResult result;

    result.attackType = "Expired Certificate";
    result.detected = true;

    result.message =
        "Command received with an expired certificate";

    return result;
}