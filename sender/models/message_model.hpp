#ifndef SENDER_MESSAGE_MODEL_HPP
#define SENDER_MESSAGE_MODEL_HPP

#include <cstdint>
#include <string>

enum class SendStatus {
    NotSent,
    Sending,
    SentToTcp,
    ConnectionFailed
};

struct MessageRecord {
    std::string id;
    std::string machine_id;
    std::string command;
    std::string timestamp_utc;
    uint64_t sequence{};
    std::string rsa_fingerprint;
    std::string ggh_fingerprint;
    size_t rsa_signature_size{};
    size_t ggh_signature_size{};
    SendStatus status{SendStatus::NotSent};
    bool is_outgoing{true};
};

#endif
