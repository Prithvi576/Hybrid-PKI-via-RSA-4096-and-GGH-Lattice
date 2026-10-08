#include <iostream>

#include "../scada/RBAC.h"
#include "../scada/ReplayProtection.h"
#include "../scada/CommandValidator.h"

void printResult(const std::string& testName, bool passed)
{
    std::cout << testName << ": "
              << (passed ? "PASS" : "FAIL")
              << std::endl;
}

int main()
{
    std::cout << "===== SCADA SECURITY INTEGRATION TEST ====="
              << std::endl;

    RBAC rbac;

    ReplayProtection replayProtection(60);

    CommandValidator validator(
        rbac,
        replayProtection
    );

    const std::uint64_t currentTime = 1000;


    // ==================================================
    // TEST 1: Operator performs an authorized command
    // ==================================================

    SCADACommand normalCommand;

    normalCommand.userId = "operator01";
    normalCommand.role = "operator";
    normalCommand.command = "START_PUMP";
    normalCommand.timestamp = 990;
    normalCommand.sequence = 1;

    bool result1 =
        validator.validate(
            normalCommand,
            currentTime
        );

    printResult(
        "1. Authorized operator command",
        result1
    );


    // ==================================================
    // TEST 2: Operator attempts unauthorized command
    // ==================================================

    SCADACommand unauthorizedCommand;

    unauthorizedCommand.userId = "operator01";
    unauthorizedCommand.role = "operator";
    unauthorizedCommand.command = "CONFIGURE_SYSTEM";
    unauthorizedCommand.timestamp = 995;
    unauthorizedCommand.sequence = 2;

    bool result2 =
        validator.validate(
            unauthorizedCommand,
            currentTime
        );

    printResult(
        "2. Unauthorized command rejected",
        !result2
    );


    // ==================================================
    // TEST 3: Replay same command
    // ==================================================

    SCADACommand replayCommand;

    replayCommand.userId = "operator01";
    replayCommand.role = "operator";
    replayCommand.command = "START_PUMP";
    replayCommand.timestamp = 990;
    replayCommand.sequence = 1;

    bool result3 =
        validator.validate(
            replayCommand,
            currentTime
        );

    printResult(
        "3. Replay attack rejected",
        !result3
    );


    // ==================================================
    // TEST 4: Old command
    // ==================================================

    SCADACommand oldCommand;

    oldCommand.userId = "operator01";
    oldCommand.role = "operator";
    oldCommand.command = "START_PUMP";
    oldCommand.timestamp = 900;
    oldCommand.sequence = 3;

    bool result4 =
        validator.validate(
            oldCommand,
            currentTime
        );

    printResult(
        "4. Old command rejected",
        !result4
    );


    // ==================================================
    // TEST 5: Engineer performs critical command
    // ==================================================

    SCADACommand engineerCommand;

    engineerCommand.userId = "engineer01";
    engineerCommand.role = "engineer";
    engineerCommand.command = "CONFIGURE_SYSTEM";
    engineerCommand.timestamp = 995;
    engineerCommand.sequence = 1;

    bool result5 =
        validator.validate(
            engineerCommand,
            currentTime
        );

    printResult(
        "5. Engineer critical command",
        result5
    );


    // ==================================================
    // TEST 6: Unknown role
    // ==================================================

    SCADACommand unknownUser;

    unknownUser.userId = "unknown01";
    unknownUser.role = "hacker";
    unknownUser.command = "START_PUMP";
    unknownUser.timestamp = 995;
    unknownUser.sequence = 1;

    bool result6 =
        validator.validate(
            unknownUser,
            currentTime
        );

    printResult(
        "6. Unknown role rejected",
        !result6
    );


    std::cout << "============================================="
              << std::endl;

    return 0;
}