
#ifndef CERTIFICATE_VALIDATOR_H
#define CERTIFICATE_VALIDATOR_H

#include <string>
#include "CertificateManager.h"

class CertificateValidator
{
private:
    std::string trustedCA;

public:
    CertificateValidator();

    void setTrustedCA(const std::string& caName);

    bool validateIssuer(const CertificateManager& certificate) const;

    bool validateCertificateFields(
        const CertificateManager& certificate,
        const std::string& expectedSerial
    ) const;

    void displayValidationResult(bool result) const;

    bool validateX509Certificate(
        const std::string& certificatePath,
        const std::string& trustedCaBundlePath,
        std::string& error
    ) const;

    // Validates the certificate and rejects it if its serial is revoked.
    bool validateX509CertificateWithRevocation(
        const std::string& certificatePath,
        const std::string& trustedCaBundlePath,
        const std::string& revokedSerialNumbersFile,
        std::string& error
    ) const;
};

#endif
