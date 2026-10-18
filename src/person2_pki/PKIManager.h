
#ifndef PKI_MANAGER_H
#define PKI_MANAGER_H

#include <string>

#include "CertificateAuthority.h"
#include "CertificateValidator.h"
#include "RevocationManager.h"

class PKIManager
{
private:
    CertificateAuthority certificateAuthority;
    CertificateValidator certificateValidator;
    RevocationManager revocationManager;
    bool initialized;

    // Paths used for real X.509 validation.
    std::string trustedCaBundlePath;
    std::string revokedSerialNumbersFile;

public:
    PKIManager();

    void initialize(
        const std::string& caName,
        const std::string& caIdentifier
    );

    // Issue a metadata certificate using the existing CA.
    CertificateManager issueCertificate(
        const std::string& subject,
        const std::string& serialNumber
    );

    // Validate an existing metadata certificate.
    bool validateCertificate(
        const CertificateManager& certificate,
        const std::string& expectedSerial
    ) const;

    // Configure real X.509 validation.
    void configureX509Validation(
        const std::string& caBundlePath,
        const std::string& revocationFilePath
    );

    // Validate a PEM certificate, its chain, and revocation status.
    bool validateX509Certificate(
        const std::string& certificatePath,
        std::string& error
    ) const;

    // Persist revocation of a hexadecimal X.509 certificate serial.
    bool revokeX509Certificate(
        const std::string& serialNumber
    );

    // Existing metadata-certificate revocation.
    bool revokeCertificate(
        const std::string& serialNumber
    );

    void displayPKIStatus() const;
};

#endif
