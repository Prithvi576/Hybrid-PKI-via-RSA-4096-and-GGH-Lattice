#include "CertificateValidator.h"
#include <iostream>

CertificateValidator::CertificateValidator()
{
    trustedCA = "";
}

void CertificateValidator::setTrustedCA(
    const std::string& caName
)
{
    trustedCA = caName;
}

bool CertificateValidator::validateIssuer(
    const CertificateManager& certificate
) const
{
    return certificate.getCertificateSummary().find(
        "Issuer: " + trustedCA
    ) != std::string::npos;
}

void CertificateValidator::displayValidationResult(
    bool result
) const
{
    if(result)
    {
        std::cout << "Certificate Validation: VALID"
                  << std::endl;
    }
    else
    {
        std::cout << "Certificate Validation: INVALID"
                  << std::endl;
    }
}