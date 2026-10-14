#include "CertificateValidator.h"

#include <iostream>

// Constructor
CertificateValidator::CertificateValidator()
    : trustedCA("")
{
}

// Set the trusted Certificate Authority
void CertificateValidator::setTrustedCA(const std::string& caName)
{
    trustedCA = caName;
}

// Validate the certificate issuer
bool CertificateValidator::validateIssuer(
    const CertificateManager& certificate) const
{
    if (trustedCA.empty())
    {
        return false;
    }

    if (certificate.getIssuer().empty())
    {
        return false;
    }

    return certificate.getIssuer() == trustedCA;
}

// Validate required certificate fields and serial number
bool CertificateValidator::validateCertificateFields(
    const CertificateManager& certificate,
    const std::string& expectedSerial) const
{
    if (expectedSerial.empty())
    {
        return false;
    }

    if (certificate.getSubject().empty())
    {
        return false;
    }

    if (certificate.getIssuer().empty())
    {
        return false;
    }

    if (certificate.getSerialNumber().empty())
    {
        return false;
    }

    if (certificate.getSerialNumber() != expectedSerial)
    {
        return false;
    }

    return true;
}

// Display validation result
void CertificateValidator::displayValidationResult(bool result) const
{
    std::cout << "\n===== CERTIFICATE VALIDATION =====\n";

    if (result)
    {
        std::cout << "Result: Certificate is valid.\n";
    }
    else
    {
        std::cout << "Result: Certificate is invalid.\n";
    }

    std::cout << "==================================\n";
}