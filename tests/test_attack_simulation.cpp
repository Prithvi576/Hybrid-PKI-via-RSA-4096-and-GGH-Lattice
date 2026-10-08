#include <iostream>

#include "../scada/AttackSimulator.h"

int main()
{
    AttackSimulator simulator;

    std::cout << "===== ATTACK SIMULATION TEST ====="
              << std::endl;

    AttackResult result1 =
        simulator.simulateUnauthorizedRole(
            "operator",
            "CONFIGURE_SYSTEM"
        );

    std::cout << "1. Unauthorized role: "
              << (result1.detected ? "DETECTED" : "MISSED")
              << std::endl;

    std::cout << "   " << result1.message << std::endl;


    AttackResult result2 =
        simulator.simulateReplayAttack();

    std::cout << "2. Replay attack: "
              << (result2.detected ? "DETECTED" : "MISSED")
              << std::endl;

    std::cout << "   " << result2.message << std::endl;


    AttackResult result3 =
        simulator.simulateModifiedCommand();

    std::cout << "3. Modified command: "
              << (result3.detected ? "DETECTED" : "MISSED")
              << std::endl;

    std::cout << "   " << result3.message << std::endl;


    AttackResult result4 =
        simulator.simulateInvalidCertificate();

    std::cout << "4. Invalid certificate: "
              << (result4.detected ? "DETECTED" : "MISSED")
              << std::endl;

    std::cout << "   " << result4.message << std::endl;


    AttackResult result5 =
        simulator.simulateExpiredCertificate();

    std::cout << "5. Expired certificate: "
              << (result5.detected ? "DETECTED" : "MISSED")
              << std::endl;

    std::cout << "   " << result5.message << std::endl;


    std::cout << "================================="
              << std::endl;

    return 0;
}