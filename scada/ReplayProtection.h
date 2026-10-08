#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>

class ReplayProtection {
public:
    explicit ReplayProtection(std::uint64_t timeWindowSeconds = 60);

    bool isTimestampValid(
        std::uint64_t timestamp,
        std::uint64_t currentTime
    ) const;

    bool isSequenceFresh(
        const std::string& userId,
        std::uint64_t sequence
    ) const;

    void markProcessed(
        const std::string& userId,
        std::uint64_t sequence
    );

private:
    std::uint64_t timeWindowSeconds;

    std::unordered_set<std::string> processedCommands;

    std::string makeSequenceKey(
        const std::string& userId,
        std::uint64_t sequence
    ) const;
};