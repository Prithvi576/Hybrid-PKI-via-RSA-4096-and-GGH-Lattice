
#ifndef CERTIFICATE_IDENTITY_MAPPER_H
#define CERTIFICATE_IDENTITY_MAPPER_H

#include <string>
#include <unordered_map>

#include "CertificateValidator.h"

class CertificateIdentityMapper
{
private:
    std::unordered_map<std::string, std::string> fingerprintToUserId;

    static bool getSha256Fingerprint(
        const std::string& certificatePath,
        std::string& fingerprint,
        std::string& error
    );

public:
    // Register a trusted certificate fingerprint for a user ID.
    // Fingerprints are normalized to uppercase hexadecimal without colons.
    bool addMapping(
        const std::string& fingerprint,
        const std::string& userId
    );

    // Validate the certificate and revocation status before mapping it.
    bool mapValidatedCertificateToUser(
        const std::string& certificatePath,
        const std::string& trustedCaBundlePath,
        const std::string& revokedSerialNumbersFile,
        std::string& userId,
        std::string& error
    ) const;

    // Calculate the SHA-256 fingerprint of a PEM certificate.
    static bool certificateFingerprint(
        const std::string& certificatePath,
        std::string& fingerprint,
        std::string& error
    );
};

#endif
