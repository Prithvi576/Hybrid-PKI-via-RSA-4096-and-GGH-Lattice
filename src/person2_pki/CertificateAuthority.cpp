#include "CertificateAuthority.h"
#include <iostream>
#include <stdexcept>

CertificateAuthority::CertificateAuthority()
    : caName(), caIdentifier(), issuedCertificates()
{
}

void CertificateAuthority::setCAInfo(
    const std::string& name,
    const std::string& identifier)
{
    if (name.empty() || identifier.empty())
        throw std::invalid_argument("CA name and identifier must not be empty.");

    caName = name;
    caIdentifier = identifier;
}

CertificateManager CertificateAuthority::issueCertificate(
    const std::string& subject,
    const std::string& serialNumber)
{
    if (caName.empty() || caIdentifier.empty())
        throw std::logic_error("Initialize the CA before issuing certificates.");
    if (subject.empty() || serialNumber.empty())
        throw std::invalid_argument("Subject and serial number must not be empty.");
    if (hasIssuedSerialNumber(serialNumber))
        throw std::invalid_argument("A certificate with this serial number already exists.");

    CertificateManager certificate;
    certificate.setCertificateInfo(subject, caName, serialNumber);
    issuedCertificates.push_back(certificate);
    return certificate;
}

bool CertificateAuthority::hasIssuedCertificate(
    const CertificateManager& certificate) const
{
    for (const CertificateManager& issued : issuedCertificates)
    {
        if (issued.getSubject() == certificate.getSubject() &&
            issued.getIssuer() == certificate.getIssuer() &&
            issued.getSerialNumber() == certificate.getSerialNumber())
            return true;
    }
    return false;
}

bool CertificateAuthority::hasIssuedSerialNumber(
    const std::string& serialNumber) const
{
    for (const CertificateManager& issued : issuedCertificates)
        if (issued.getSerialNumber() == serialNumber)
            return true;
    return false;
}

void CertificateAuthority::displayCAInfo() const
{
    std::cout << "----- Certificate Authority -----\n"
              << "CA Name       : " << caName << '\n'
              << "CA Identifier : " << caIdentifier << '\n'
              << "---------------------------------\n";
}

void CertificateAuthority::displayIssuedCertificates() const
{
    std::cout << "\n----- Issued Certificates -----\n";
    if (issuedCertificates.empty())
        std::cout << "No certificates issued.\n";
    else
        for (const CertificateManager& certificate : issuedCertificates)
            certificate.displayCertificateInfo();
    std::cout << "-------------------------------\n";
}
