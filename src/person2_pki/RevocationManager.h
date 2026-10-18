
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

    // Existing in-memory revocation.
    bool revokeCertificate(const std::string& serialNumber);
    bool isRevoked(const std::string& serialNumber) const;

    // Persist a hexadecimal certificate serial to a revocation file.
    // Returns false if the file cannot be read or written.
    bool revokeCertificateInFile(
        const std::string& serialNumber,
        const std::string& revocationFilePath
    ) const;

    void displayRevokedCertificates() const;
};

#endif
