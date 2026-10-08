#include "../scada/SecurityLogger.h"

int main()
{
    SecurityLogger logger;

    logger.info("Certificate validation PASS");

    logger.info("Identity validation PASS");

    logger.info("RBAC validation PASS");

    logger.warning(
        "RBAC validation FAIL: "
        "operator attempted CONFIGURE_SYSTEM"
    );

    logger.info("Replay protection PASS");

    logger.warning(
        "Replay attack detected for user operator01"
    );

    logger.alert(
        "Modified command detected"
    );

    logger.alert(
        "Invalid certificate detected"
    );

    logger.info(
        "Command START_PUMP accepted and executed"
    );

    logger.warning(
        "Command CONFIGURE_SYSTEM rejected"
    );

    return 0;
}