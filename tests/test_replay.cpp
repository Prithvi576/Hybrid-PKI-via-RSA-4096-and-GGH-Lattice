#include <iostream>
#include "../scada/ReplayProtection.h"

int main()
{
    ReplayProtection replayProtection(60);

    std::string userId = "operator01";

    std::uint64_t currentTime = 1000;

    // -------------------------------
    // Test 1: Fresh timestamp
    // -------------------------------

    bool timestampValid =
        replayProtection.isTimestampValid(
            970,
            currentTime
        );

    std::cout << "Fresh timestamp: "
              << (timestampValid ? "PASS" : "FAIL")
              << std::endl;


    // -------------------------------
    // Test 2: Old timestamp
    // -------------------------------

    bool oldTimestamp =
        replayProtection.isTimestampValid(
            900,
            currentTime
        );

    std::cout << "Old timestamp rejected: "
              << (!oldTimestamp ? "PASS" : "FAIL")
              << std::endl;


    // -------------------------------
    // Test 3: First sequence
    // -------------------------------

    bool firstSequence =
        replayProtection.isSequenceFresh(
            userId,
            10
        );

    std::cout << "First sequence accepted: "
              << (firstSequence ? "PASS" : "FAIL")
              << std::endl;


    // Mark command as processed
    replayProtection.markProcessed(
        userId,
        10
    );


    // -------------------------------
    // Test 4: Replay same sequence
    // -------------------------------

    bool replay =
        replayProtection.isSequenceFresh(
            userId,
            10
        );

    std::cout << "Replay rejected: "
              << (!replay ? "PASS" : "FAIL")
              << std::endl;


    // -------------------------------
    // Test 5: New sequence
    // -------------------------------

    bool newSequence =
        replayProtection.isSequenceFresh(
            userId,
            11
        );

    std::cout << "New sequence accepted: "
              << (newSequence ? "PASS" : "FAIL")
              << std::endl;


    return 0;
}