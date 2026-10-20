
#include <iostream>
#include <string>

#include "../scada/AttackSimulator.h"

int main()
{
    AttackSimulator simulator;
    int failures = 0;

    std::cout << "===== ATTACK SIMULATION TEST ====="
              << std::endl;

    // 1. Unauthorized role attack
    AttackResult result1 =
        simulator.simulateUnauthorizedRole(
            "operator",
            "CONFIGURE_SYSTEM"
        );

    std::cout << "1. Unauthorized role: "
              << (result1.detected ? "DETECTED" : "MISSED")
              << std::endl;
    std::cout << "   " << result1.message << std::endl;

    if (!result1.detected)
        ++failures;

    // 2. Replay attack
    AttackResult result2 =
        simulator.simulateReplayAttack();

    std::cout << "2. Replay attack: "
              << (result2.detected ? "DETECTED" : "MISSED")
              << std::endl;
    std::cout << "   " << result2.message << std::endl;

    if (!result2.detected)
        ++failures;

    // 3. Modified command attack
    AttackResult result3 =
        simulator.simulateModifiedCommand();

    std::cout << "3. Modified command: "
              << (result3.detected ? "DETECTED" : "MISSED")
              << std::endl;
    std::cout << "   " << result3.message << std::endl;

    if (!result3.detected)
        ++failures;

    // 4. Invalid certificate attack
    AttackResult result4 =
        simulator.simulateInvalidCertificate();

    std::cout << "4. Invalid certificate: "
              << (result4.detected ? "DETECTED" : "MISSED")
              << std::endl;
    std::cout << "   " << result4.message << std::endl;

    if (!result4.detected)
        ++failures;

    // 5. Expired certificate attack
    AttackResult result5 =
        simulator.simulateExpiredCertificate();

    std::cout << "5. Expired certificate: "
              << (result5.detected ? "DETECTED" : "MISSED")
              << std::endl;
    std::cout << "   " << result5.message << std::endl;
    if (!result5.detected)
    ++failures;

    std::cout << "================================="
              << std::endl;

    if (failures == 0)
    {
        std::cout << "RESULT: ALL 5 ATTACK CHECKS PASSED"
                  << std::endl;
        return 0;
    }

    std::cout << "RESULT: " << failures
              << " ATTACK CHECK(S) FAILED"
              << std::endl;

    return 1;
}
