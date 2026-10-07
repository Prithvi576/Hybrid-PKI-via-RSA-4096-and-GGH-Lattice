#ifndef PKI_MANAGER_H
#define PKI_MANAGER_H

#include "CertificateAuthority.h"
#include "CertificateValidator.h"
#include "RevocationManager.h"

class PKIManager
{
private:

    CertificateAuthority certificateAuthority;
    CertificateValidator certificateValidator;
    RevocationManager revocationManager;

public:

    PKIManager();

    void initialize(
        const std::string& caName,
        const std::string& caIdentifier
    );

    CertificateManager issueCertificate(
        const std::string& subject,
        const std::string& serialNumber
    );

    bool validateCertificate(
        const CertificateManager& certificate,
        const std::string& serialNumber
    ) const;

    void revokeCertificate(
        const std::string& serialNumber
    );

    void displayPKIStatus() const;
};

#endif