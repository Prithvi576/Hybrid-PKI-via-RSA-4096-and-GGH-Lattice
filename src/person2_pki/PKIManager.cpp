#include "PKIManager.h"

#include <iostream>
#include <stdexcept>

// Constructor
PKIManager::PKIManager()
    : certificateAuthority(),
      certificateValidator(),
      revocationManager(),
      initialized(false)
{
}

// Initialize the PKI system
void PKIManager::initialize(
    const std::string& caName,
    const std::string& caIdentifier)
{
    // Reject invalid CA information
    if (caName.empty() || caIdentifier.empty())
    {
        throw std::invalid_argument(
            "CA name and identifier cannot be empty."
        );
    }

    // Prevent changing the CA after initialization
    if (initialized)
    {
        throw std::logic_error(
            "PKI has already been initialized."
        );
    }

    certificateAuthority.setCAInfo(caName, caIdentifier);
    certificateValidator.setTrustedCA(caName);

    initialized = true;
}

// Issue a certificate
CertificateManager PKIManager::issueCertificate(
    const std::string& subject,
    const std::string& serialNumber)
{
    if (!initialized)
    {
        throw std::logic_error(
            "Initialize PKI before issuing certificates."
        );
    }

    if (subject.empty() || serialNumber.empty())
    {
        throw std::invalid_argument(
            "Subject and serial number cannot be empty."
        );
    }

    return certificateAuthority.issueCertificate(
        subject,
        serialNumber
    );
}

// Validate a certificate
bool PKIManager::validateCertificate(
    const CertificateManager& certificate,
    const std::string& expectedSerial) const
{
    if (!initialized || expectedSerial.empty())
    {
        return false;
    }

    // Validate the certificate's fields and expected serial
    if (!certificateValidator.validateCertificateFields(
            certificate, expectedSerial))
    {
        return false;
    }

    // Ensure the certificate claims the trusted CA as issuer
    if (!certificateValidator.validateIssuer(certificate))
    {
        return false;
    }

    // Ensure this CA actually issued the certificate
    if (!certificateAuthority.hasIssuedCertificate(certificate))
    {
        return false;
    }

    // Reject revoked certificates
    if (revocationManager.isRevoked(
            certificate.getSerialNumber()))
    {
        return false;
    }

    return true;
}

// Revoke a certificate
bool PKIManager::revokeCertificate(
    const std::string& serialNumber)
{
    if (!initialized || serialNumber.empty())
    {
        return false;
    }

    // Only revoke certificates issued by this CA
    if (!certificateAuthority.hasIssuedSerialNumber(serialNumber))
    {
        return false;
    }

    // RevocationManager handles duplicate revocation
    return revocationManager.revokeCertificate(serialNumber);
}

// Display PKI status
void PKIManager::displayPKIStatus() const
{
    std::cout << "\n========== PKI STATUS ==========\n";

    if (!initialized)
    {
        std::cout << "PKI Status: Not initialized\n";
        std::cout << "================================\n";
        return;
    }

    std::cout << "PKI Status: Initialized\n";

    certificateAuthority.displayCAInfo();
    certificateAuthority.displayIssuedCertificates();
    revocationManager.displayRevokedCertificates();

    std::cout << "\n================================\n";
}