
#include "PKIManager.h"

#include <iostream>
#include <stdexcept>

PKIManager::PKIManager()
    : certificateAuthority(),
      certificateValidator(),
      revocationManager(),
      initialized(false),
      trustedCaBundlePath(),
      revokedSerialNumbersFile()
{
}

void PKIManager::initialize(
    const std::string& caName,
    const std::string& caIdentifier)
{
    if (caName.empty() || caIdentifier.empty())
    {
        throw std::invalid_argument(
            "CA name and identifier cannot be empty."
        );
    }

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

bool PKIManager::validateCertificate(
    const CertificateManager& certificate,
    const std::string& expectedSerial) const
{
    if (!initialized || expectedSerial.empty())
    {
        return false;
    }

    // Check metadata fields and the expected serial.
    if (!certificateValidator.validateCertificateFields(
            certificate, expectedSerial))
    {
        return false;
    }

    // Check the trusted issuer name.
    if (!certificateValidator.validateIssuer(certificate))
    {
        return false;
    }

    // Check that this CA issued the metadata certificate.
    if (!certificateAuthority.hasIssuedCertificate(certificate))
    {
        return false;
    }

    // Reject metadata certificates revoked in memory.
    if (revocationManager.isRevoked(
            certificate.getSerialNumber()))
    {
        return false;
    }

    return true;
}

void PKIManager::configureX509Validation(
    const std::string& caBundlePath,
    const std::string& revocationFilePath)
{
    if (caBundlePath.empty() || revocationFilePath.empty())
    {
        throw std::invalid_argument(
            "CA bundle and revocation file paths cannot be empty."
        );
    }

    trustedCaBundlePath = caBundlePath;
    revokedSerialNumbersFile = revocationFilePath;
}

bool PKIManager::validateX509Certificate(
    const std::string& certificatePath,
    std::string& error) const
{
    error.clear();

    if (!initialized)
    {
        error = "Initialize PKI before validating certificates.";
        return false;
    }

    if (certificatePath.empty())
    {
        error = "Certificate path cannot be empty.";
        return false;
    }

    if (trustedCaBundlePath.empty() ||
        revokedSerialNumbersFile.empty())
    {
        error = "X.509 validation paths have not been configured.";
        return false;
    }

    return certificateValidator.validateX509CertificateWithRevocation(
        certificatePath,
        trustedCaBundlePath,
        revokedSerialNumbersFile,
        error
    );
}

bool PKIManager::revokeX509Certificate(
    const std::string& serialNumber)
{
    if (!initialized ||
        serialNumber.empty() ||
        revokedSerialNumbersFile.empty())
    {
        return false;
    }

    return revocationManager.revokeCertificateInFile(
        serialNumber,
        revokedSerialNumbersFile
    );
}

bool PKIManager::revokeCertificate(
    const std::string& serialNumber)
{
    if (!initialized || serialNumber.empty())
    {
        return false;
    }

    // This method handles metadata certificates only.
    if (!certificateAuthority.hasIssuedSerialNumber(serialNumber))
    {
        return false;
    }

    return revocationManager.revokeCertificate(serialNumber);
}

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
