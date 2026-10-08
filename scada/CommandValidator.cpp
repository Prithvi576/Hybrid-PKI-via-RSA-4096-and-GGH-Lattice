#include "CommandValidator.h"

CommandValidator::CommandValidator(
    RBAC& rbac,
    ReplayProtection& replayProtection
)
    : rbac(rbac),
      replayProtection(replayProtection)
{
}

bool CommandValidator::validate(
    const SCADACommand& command,
    std::uint64_t currentTime
)
{
    // 1. RBAC authorization
    if (!rbac.isAuthorized(command.role, command.command))
    {
        return false;
    }

    // 2. Timestamp validation
    if (!replayProtection.isTimestampValid(
            command.timestamp,
            currentTime))
    {
        return false;
    }

    // 3. Sequence-number freshness
    if (!replayProtection.isSequenceFresh(
            command.userId,
            command.sequence))
    {
        return false;
    }

    // 4. Mark command as processed
    replayProtection.markProcessed(
        command.userId,
        command.sequence
    );

    return true;
}