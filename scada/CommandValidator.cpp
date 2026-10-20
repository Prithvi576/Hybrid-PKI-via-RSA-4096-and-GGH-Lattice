#include "CommandValidator.h"
#include "SecurityLogger.h"

CommandValidator::CommandValidator(
    RBAC& rbac,
    ReplayProtection& replayProtection,
    SecurityLogger* logger
)
    : rbac(rbac),
      replayProtection(replayProtection),
      logger(logger)
{
}

bool CommandValidator::validate(
    const SCADACommand& command,
    std::uint64_t currentTime
)
{
    if (!rbac.isAuthorized(command.role, command.command))
    {
        if (logger)
            logger->warning("RBAC rejected command from user " +
                            command.userId);
        return false;
    }

    if (!replayProtection.isTimestampValid(
            command.timestamp, currentTime))
    {
        if (logger)
            logger->warning("Invalid or expired timestamp for user " +
                            command.userId);
        return false;
    }

    if (!replayProtection.isSequenceFresh(
            command.userId, command.sequence))
    {
        if (logger)
            logger->warning("Replay detected for user " +
                            command.userId);
        return false;
    }

    replayProtection.markProcessed(
        command.userId, command.sequence);

    if (logger)
        logger->info("Command " + command.command +
                     " accepted for user " + command.userId);

    return true;
}