#include "crypto_api.hpp"

#include <chrono>
#include <stdexcept>
#include <string>

using namespace std;

namespace hybrid_pki {

namespace {
void validateField(const string& value, const char* name, const size_t maximum_length) {
    if (value.empty() || value.size() > maximum_length || value.find_first_of("\r\n") != string::npos) {
        throw invalid_argument(string("invalid ") + name);
    }
}
}  // namespace

string canonicalize(const CommandEnvelope& envelope) {
    validateField(envelope.command, "command", 128);
    validateField(envelope.timestamp_utc, "timestamp", 64);
    return "COMMAND_LENGTH=" + to_string(envelope.command.size()) + "\nCOMMAND=" +
           envelope.command + "\nTIMESTAMP_LENGTH=" + to_string(envelope.timestamp_utc.size()) +
           "\nTIMESTAMP=" + envelope.timestamp_utc + "\nSEQUENCE=" +
           to_string(envelope.sequence) + "\n";
}

HybridSigningResult hybridSign(const CommandEnvelope& envelope, const RSAKeyPair& rsa_key_pair,
                               const GGHKeyPair& ggh_key_pair) {
    const string message = canonicalize(envelope);
    const auto hybrid_start = chrono::steady_clock::now();
    const auto rsa_start = chrono::steady_clock::now();
    auto rsa_signature = signRSA(message, rsa_key_pair);
    const auto rsa_end = chrono::steady_clock::now();
    const auto ggh_start = chrono::steady_clock::now();
    auto ggh_signature = signGGH(message, ggh_key_pair);
    const auto ggh_end = chrono::steady_clock::now();

    HybridSigningResult result;
    result.signed_command = {envelope, move(rsa_signature), move(ggh_signature)};
    result.measurements.rsa = chrono::duration_cast<chrono::nanoseconds>(rsa_end - rsa_start);
    result.measurements.ggh = chrono::duration_cast<chrono::nanoseconds>(ggh_end - ggh_start);
    result.measurements.hybrid =
        chrono::duration_cast<chrono::nanoseconds>(ggh_end - hybrid_start);
    return result;
}

}  // namespace hybrid_pki
