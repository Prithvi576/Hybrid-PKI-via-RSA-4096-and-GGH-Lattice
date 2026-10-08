#include <iostream>

#include "../scada/RBAC.h"
#include "../scada/ReplayProtection.h"
#include "../scada/CommandValidator.h"

int main()
{
    RBAC rbac;

    ReplayProtection replayProtection(60);

    CommandValidator validator(
        rbac,
        replayProtection
    );

    std::uint64_t currentTime = 1000;


    // --------------------------------
    // Test 1: Authorized command
    // --------------------------------

    SCADACommand command1;

    command1.userId = "operator01";
    command1.role = "operator";
    command1.command = "START_PUMP";
    command1.timestamp = 990;
    command1.sequence = 1;

    bool result1 =
        validator.validate(
            command1,
            currentTime
        );

    std::cout << "Authorized command: "
              << (result1 ? "PASS" : "FAIL")
              << std::endl;


    // --------------------------------
    // Test 2: Unauthorized command
    // --------------------------------

    SCADACommand command2;

    command2.userId = "operator01";
    command2.role = "operator";
    command2.command = "CONFIGURE_SYSTEM";
    command2.timestamp = 995;
    command2.sequence = 2;

    bool result2 =
        validator.validate(
            command2,
            currentTime
        );

    std::cout << "Unauthorized command rejected: "
              << (!result2 ? "PASS" : "FAIL")
              << std::endl;


    // --------------------------------
    // Test 3: Replay attack
    // --------------------------------

    SCADACommand command3;

    command3.userId = "operator01";
    command3.role = "operator";
    command3.command = "START_PUMP";
    command3.timestamp = 990;
    command3.sequence = 1;

    bool result3 =
        validator.validate(
            command3,
            currentTime
        );

    std::cout << "Replay attack rejected: "
              << (!result3 ? "PASS" : "FAIL")
              << std::endl;


    // --------------------------------
    // Test 4: Old command
    // --------------------------------

    SCADACommand command4;

    command4.userId = "operator01";
    command4.role = "operator";
    command4.command = "START_PUMP";
    command4.timestamp = 900;
    command4.sequence = 3;

    bool result4 =
        validator.validate(
            command4,
            currentTime
        );

    std::cout << "Old command rejected: "
              << (!result4 ? "PASS" : "FAIL")
              << std::endl;


    // --------------------------------
    // Test 5: Engineer critical command
    // --------------------------------

    SCADACommand command5;

    command5.userId = "engineer01";
    command5.role = "engineer";
    command5.command = "CONFIGURE_SYSTEM";
    command5.timestamp = 995;
    command5.sequence = 1;

    bool result5 =
        validator.validate(
            command5,
            currentTime
        );

    std::cout << "Engineer critical command: "
              << (result5 ? "PASS" : "FAIL")
              << std::endl;


    return 0;
}