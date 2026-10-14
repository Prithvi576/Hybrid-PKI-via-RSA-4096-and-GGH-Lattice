#include "CertificateValidator.h"
#include <iostream>

CertificateValidator::CertificateValidator()
    : trustedCA()
{
}

void CertificateValidator::setTrustedCA(const std::string& caName)
{
    trustedCA = caName;
}

bool CertificateValidator::validateIssuer(
    const CertificateManager& certificate) const
{
    return !trustedCA.empty() && certificate.getIssuer() == trustedCA;
}

bool CertificateValidator::validateCertificateFields(
    const CertificateManager& certificate,
    const std::string& expectedSerial) const
{
    return certificate.validateCertificate() &&
           !expectedSerial.empty() &&
           certificate.getSerialNumber() == expectedSerial;
}

void CertificateValidator::displayValidationResult(bool result) const
{
    std::cout << "Certificate Validation: "
              << (result ? "VALID" : "INVALID") << '\n';
}
