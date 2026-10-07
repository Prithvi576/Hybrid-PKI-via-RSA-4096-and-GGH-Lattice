#include "CertificateAuthority.h"
#include <iostream>

CertificateAuthority::CertificateAuthority()
{
    caName = "";
    caIdentifier = "";
}

void CertificateAuthority::setCAInfo(
    const std::string& name,
    const std::string& identifier
)
{
    caName = name;
    caIdentifier = identifier;
}

CertificateManager CertificateAuthority::issueCertificate(
    const std::string& subject,
    const std::string& serialNumber
)
{
    CertificateManager certificate;

    certificate.setCertificateInfo(
        subject,
        caName,
        serialNumber
    );

    issuedCertificates.push_back(certificate);

    return certificate;
}

void CertificateAuthority::displayCAInfo() const
{
    std::cout << "----- Certificate Authority -----"
              << std::endl;

    std::cout << "CA Name       : "
              << caName
              << std::endl;

    std::cout << "CA Identifier : "
              << caIdentifier
              << std::endl;

    std::cout << "---------------------------------"
              << std::endl;
}

void CertificateAuthority::displayIssuedCertificates() const
{
    std::cout << std::endl;
    std::cout << "----- Issued Certificates -----"
              << std::endl;

    for(const CertificateManager& certificate : issuedCertificates)
    {
        certificate.displayCertificateInfo();
    }

    std::cout << "-------------------------------"
              << std::endl;
}