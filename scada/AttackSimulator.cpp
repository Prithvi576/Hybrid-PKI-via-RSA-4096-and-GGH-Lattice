
#include "AttackSimulator.h"

#include "RBAC.h"
#include "ReplayProtection.h"
#include "../crypto/crypto_api.hpp"
#include "../src/person2_pki/CertificateValidator.h"

#include <cstdint>
#include <exception>
#include <string>

AttackResult AttackSimulator::simulateUnauthorizedRole(
    const std::string& role,
    const std::string& command)
{
    AttackResult result;
    result.attackType = "Unauthorized Role";

    RBAC rbac;
    const bool authorized = rbac.isAuthorized(role, command);

    result.detected = !authorized;
    result.message = authorized
        ? "RBAC allowed the command; attack was NOT detected"
        : "RBAC rejected unauthorized command '" + command +
          "' for role '" + role + "'";

    return result;
}

AttackResult AttackSimulator::simulateReplayAttack()
{
    AttackResult result;
    result.attackType = "Replay Attack";

    ReplayProtection protection(60);

    const std::string userId = "operator01";
    const std::uint64_t timestamp = 990;
    const std::uint64_t sequence = 1;
    const std::uint64_t currentTime = 1000;

    // Establish that the original command is valid.
    const bool timestampValid =
        protection.isTimestampValid(timestamp, currentTime);
    const bool sequenceFresh =
        protection.isSequenceFresh(userId, sequence);

    if (!timestampValid || !sequenceFresh) {
        result.detected = false;
        result.message =
            "Could not establish a valid original command for replay test";
        return result;
    }

    protection.markProcessed(userId, sequence);

    // Attempt to replay the same command.
    const bool replayTimestampValid =
        protection.isTimestampValid(timestamp, currentTime);
    const bool replaySequenceFresh =
        protection.isSequenceFresh(userId, sequence);

    result.detected =
        replayTimestampValid && !replaySequenceFresh;

    result.message = result.detected
        ? "ReplayProtection rejected the previously processed sequence"
        : "Replay was not rejected by ReplayProtection";

    return result;
}

AttackResult AttackSimulator::simulateModifiedCommand()
{
    AttackResult result;
    result.attackType = "Modified Command";

    try {
        const auto rsaKey = hybrid_pki::generateRSAKeyPair();
        const auto gghKey = hybrid_pki::generateGGHKeyPair();

        const hybrid_pki::CommandEnvelope original{
            "OPEN_VALVE",
            "2026-10-07T18:00:00Z",
            105
        };

        auto signedResult =
            hybrid_pki::hybridSign(original, rsaKey, gghKey);

        // Verify the original command before tampering.
        const auto originalVerification =
            hybrid_pki::hybridVerify(
                signedResult.signed_command, rsaKey, gghKey);

        if (!originalVerification.overall_valid) {
            result.detected = false;
            result.message =
                "Could not establish a valid signed command";
            return result;
        }

        // Change the command after signing.
        signedResult.signed_command.envelope.command = "CLOSE_VALVE";

        const auto tamperedVerification =
            hybrid_pki::hybridVerify(
                signedResult.signed_command, rsaKey, gghKey);

        result.detected = !tamperedVerification.overall_valid;
        result.message = result.detected
            ? "Hybrid signature verification rejected the modified command"
            : "Modified command was not rejected by signature verification";
    }
    catch (const std::exception& error) {
        result.detected = false;
        result.message =
            std::string("Cryptographic test could not run: ") + error.what();
    }
    catch (...) {
        result.detected = false;
        result.message = "Cryptographic test failed with an unknown error";
    }

    return result;
}

AttackResult AttackSimulator::simulateInvalidCertificate()
{
    AttackResult result;
    result.attackType = "Invalid Certificate";

    CertificateValidator validator;
    std::string error;

    const bool accepted = validator.validateX509Certificate(
        "pki_test_certs/test_client.pem",
        "pki_test_certs/test_wrong_ca.pem",
        error
    );

    // A missing fixture is a test setup error, not a detected attack.
    const bool fixtureMissing =
        error.find("Cannot open certificate file") != std::string::npos ||
        error.find("No such file") != std::string::npos ||
        error.find("No such process") != std::string::npos;

    result.detected = !accepted && !fixtureMissing;

    result.message = result.detected
        ? "Certificate validation rejected the invalid certificate: " + error
        : (accepted
            ? "Invalid certificate was accepted; detection failed"
            : "Invalid-certificate test could not validate its fixture: " + error);

    return result;
}

AttackResult AttackSimulator::simulateExpiredCertificate()
{
    AttackResult result;
    result.attackType = "Expired Certificate";

    CertificateValidator validator;
    std::string error;

    const bool accepted = validator.validateX509Certificate(
        "pki_test_certs/test_expired.pem",
        "pki_test_certs/test_ca.pem",
        error
    );

    // Only an explicit expiration error counts as detection.
    // Missing files or other validation failures must not pass.
    const bool expirationConfirmed =
        error.find("certificate has expired") != std::string::npos;

    result.detected = !accepted && expirationConfirmed;

    result.message = result.detected
        ? "Expired certificate correctly rejected: " + error
        : (accepted
            ? "Expired certificate was accepted; detection failed"
            : "Certificate rejected, but expiration was not confirmed: " + error);

    return result;
}
