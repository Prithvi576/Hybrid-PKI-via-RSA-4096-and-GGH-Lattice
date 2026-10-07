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

    void setTrustedCA(
        const std::string& caName
    );

    bool validateIssuer(
        const CertificateManager& certificate
    ) const;

    void displayValidationResult(
        bool result
    ) const;
};

#endif