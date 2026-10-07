#ifndef REVOCATION_MANAGER_H
#define REVOCATION_MANAGER_H

#include <string>
#include <vector>

class RevocationManager
{
private:

    std::vector<std::string> revokedSerialNumbers;

public:

    RevocationManager();

    void revokeCertificate(
        const std::string& serialNumber
    );

    bool isRevoked(
        const std::string& serialNumber
    ) const;

    void displayRevokedCertificates() const;
};

#endif