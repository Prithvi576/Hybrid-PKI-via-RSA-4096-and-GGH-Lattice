#ifndef CERTIFICATE_AUTHORITY_H
#define CERTIFICATE_AUTHORITY_H

#include <string>
#include <vector>

#include "CertificateManager.h"

class CertificateAuthority
{
private:

    std::string caName;
    std::string caIdentifier;

    std::vector<CertificateManager> issuedCertificates;

public:

    CertificateAuthority();

    void setCAInfo(
        const std::string& name,
        const std::string& identifier
    );

    CertificateManager issueCertificate(
        const std::string& subject,
        const std::string& serialNumber
    );

    void displayCAInfo() const;

    void displayIssuedCertificates() const;
};

#endif