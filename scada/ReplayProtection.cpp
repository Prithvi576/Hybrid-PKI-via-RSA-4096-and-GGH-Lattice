#include "ReplayProtection.h"

ReplayProtection::ReplayProtection(
    std::uint64_t timeWindowSeconds)
    : timeWindowSeconds(timeWindowSeconds)
{
}


bool ReplayProtection::isTimestampValid(
    std::uint64_t timestamp,
    std::uint64_t currentTime) const
{
    // Future timestamp
    if (timestamp > currentTime)
        return false;

    // Command is too old
    if (currentTime - timestamp > timeWindowSeconds)
        return false;

    return true;
}


std::string ReplayProtection::makeSequenceKey(
    const std::string& userId,
    std::uint64_t sequence) const
{
    return userId + ":" + std::to_string(sequence);
}


bool ReplayProtection::isSequenceFresh(
    const std::string& userId,
    std::uint64_t sequence) const
{
    std::string key =
        makeSequenceKey(userId, sequence);

    return processedCommands.find(key)
           == processedCommands.end();
}


void ReplayProtection::markProcessed(
    const std::string& userId,
    std::uint64_t sequence)
{
    std::string key =
        makeSequenceKey(userId, sequence);

    processedCommands.insert(key);
}