#include "PKIManager.h"
#include <iostream>

PKIManager::PKIManager()
{
}

void PKIManager::initialize(
    const std::string& caName,
    const std::string& caIdentifier
)
{
    certificateAuthority.setCAInfo(
        caName,
        caIdentifier
    );

    certificateValidator.setTrustedCA(
        caName
    );
}

CertificateManager PKIManager::issueCertificate(
    const std::string& subject,
    const std::string& serialNumber
)
{
    return certificateAuthority.issueCertificate(
        subject,
        serialNumber
    );
}

bool PKIManager::validateCertificate(
    const CertificateManager& certificate,
    const std::string& serialNumber
) const
{
    bool issuerValid =
        certificateValidator.validateIssuer(
            certificate
        );

    bool certificateRevoked =
        revocationManager.isRevoked(
            serialNumber
        );

    return issuerValid && !certificateRevoked;
}

void PKIManager::revokeCertificate(
    const std::string& serialNumber
)
{
    revocationManager.revokeCertificate(
        serialNumber
    );
}

void PKIManager::displayPKIStatus() const
{
    std::cout << "===== PKI STATUS ====="
              << std::endl;

    certificateAuthority.displayCAInfo();

    revocationManager.displayRevokedCertificates();

    std::cout << "======================"
              << std::endl;
}