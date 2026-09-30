#ifndef CERTIFICATE_MANAGER_H
#define CERTIFICATE_MANAGER_H

#include <string>

class CertificateManager {
private:
    std::string subject;
    std::string issuer;
    std::string serialNumber;

public:
    CertificateManager();

    void setCertificateInfo(
        const std::string& subject,
        const std::string& issuer,
        const std::string& serialNumber
    );

    void displayCertificateInfo() const;

    bool validateCertificate() const;
};

#endif