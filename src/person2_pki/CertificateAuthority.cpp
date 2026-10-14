#include "CertificateAuthority.h"

#include <iostream>
#include <stdexcept>

// Constructor
CertificateAuthority::CertificateAuthority()
    : caName(""),
      caIdentifier(""),
      issuedCertificates()
{
}

// Set Certificate Authority information
void CertificateAuthority::setCAInfo(
    const std::string& name,
    const std::string& identifier)
{
    if (name.empty() || identifier.empty())
    {
        throw std::invalid_argument(
            "CA name and identifier cannot be empty."
        );
    }

    caName = name;
    caIdentifier = identifier;
}

// Check whether a serial number has already been issued
bool CertificateAuthority::hasIssuedSerialNumber(
    const std::string& serialNumber) const
{
    for (const CertificateManager& certificate : issuedCertificates)
    {
        if (certificate.getSerialNumber() == serialNumber)
        {
            return true;
        }
    }

    return false;
}

// Issue a certificate
CertificateManager CertificateAuthority::issueCertificate(
    const std::string& subject,
    const std::string& serialNumber)
{
    if (caName.empty() || caIdentifier.empty())
    {
        throw std::logic_error(
            "Certificate Authority must be initialized first."
        );
    }

    if (subject.empty() || serialNumber.empty())
    {
        throw std::invalid_argument(
            "Subject and serial number cannot be empty."
        );
    }

    if (hasIssuedSerialNumber(serialNumber))
    {
        throw std::invalid_argument(
            "Duplicate certificate serial number: " + serialNumber
        );
    }

    CertificateManager certificate;

    certificate.setCertificateInfo(
        subject,
        caName,
        serialNumber
    );

    issuedCertificates.push_back(certificate);

    return certificate;
}

// Check whether a certificate was issued by this CA
bool CertificateAuthority::hasIssuedCertificate(
    const CertificateManager& certificate) const
{
    for (const CertificateManager& issued : issuedCertificates)
    {
        if (issued.getSerialNumber() == certificate.getSerialNumber() &&
            issued.getSubject() == certificate.getSubject() &&
            issued.getIssuer() == certificate.getIssuer())
        {
            return true;
        }
    }

    return false;
}

// Display CA information
void CertificateAuthority::displayCAInfo() const
{
    std::cout << "\n===== CERTIFICATE AUTHORITY =====\n";
    std::cout << "CA Name       : " << caName << '\n';
    std::cout << "CA Identifier : " << caIdentifier << '\n';
    std::cout << "Certificates  : " << issuedCertificates.size() << '\n';
    std::cout << "=================================\n";
}

// Display all issued certificates
void CertificateAuthority::displayIssuedCertificates() const
{
    std::cout << "\n===== ISSUED CERTIFICATES =====\n";

    if (issuedCertificates.empty())
    {
        std::cout << "No certificates have been issued.\n";
        return;
    }

    for (const CertificateManager& certificate : issuedCertificates)
    {
        std::cout << "Subject : "
                  << certificate.getSubject() << '\n';

        std::cout << "Issuer  : "
                  << certificate.getIssuer() << '\n';

        std::cout << "Serial  : "
                  << certificate.getSerialNumber() << '\n';

        std::cout << "-------------------------------\n";
    }
}