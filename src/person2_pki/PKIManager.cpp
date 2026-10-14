#include "PKIManager.h"
#include <iostream>
#include <stdexcept>

PKIManager::PKIManager()
    : certificateAuthority(),
      certificateValidator(),
      revocationManager(),
      initialized(false)
{
}

void PKIManager::initialize(
    const std::string& caName,
    const std::string& caIdentifier)
{
    certificateAuthority.setCAInfo(caName, caIdentifier);
    certificateValidator.setTrustedCA(caName);
    initialized = true;
}

CertificateManager PKIManager::issueCertificate(
    const std::string& subject,
    const std::string& serialNumber)
{
    if (!initialized)
        throw std::logic_error("Initialize PKI before issuing certificates.");

    return certificateAuthority.issueCertificate(subject, serialNumber);
}

bool PKIManager::validateCertificate(
    const CertificateManager& certificate,
    const std::string& expectedSerial) const
{
    if (!initialized)
        return false;

    if (!certificateValidator.validateCertificateFields(certificate, expectedSerial))
        return false;

    if (!certificateValidator.validateIssuer(certificate))
        return false;

    if (!certificateAuthority.hasIssuedCertificate(certificate))
        return false;

    if (revocationManager.isRevoked(certificate.getSerialNumber()))
        return false;

    return true;
}

bool PKIManager::revokeCertificate(const std::string& serialNumber)
{
    if (!initialized || serialNumber.empty())
        return false;

    if (!certificateAuthority.hasIssuedSerialNumber(serialNumber))
        return false;

    return revocationManager.revokeCertificate(serialNumber);
}

void PKIManager::displayPKIStatus() const
{
    std::cout << "===== PKI STATUS =====\n";
    certificateAuthority.displayCAInfo();
    certificateAuthority.displayIssuedCertificates();
    revocationManager.displayRevokedCertificates();
    std::cout << "======================\n";
}
