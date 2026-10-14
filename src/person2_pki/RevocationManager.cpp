#include "RevocationManager.h"
#include <iostream>

RevocationManager::RevocationManager()
    : revokedSerialNumbers()
{
}

bool RevocationManager::revokeCertificate(const std::string& serialNumber)
{
    if (serialNumber.empty() || isRevoked(serialNumber))
        return false;

    revokedSerialNumbers.push_back(serialNumber);
    return true;
}

bool RevocationManager::isRevoked(const std::string& serialNumber) const
{
    for (const std::string& revokedSerial : revokedSerialNumbers)
        if (revokedSerial == serialNumber)
            return true;
    return false;
}

void RevocationManager::displayRevokedCertificates() const
{
    std::cout << "----- Revoked Certificates -----\n";
    if (revokedSerialNumbers.empty())
        std::cout << "No revoked certificates.\n";
    else
        for (const std::string& serialNumber : revokedSerialNumbers)
            std::cout << "Serial Number: " << serialNumber << '\n';
    std::cout << "--------------------------------\n";
}
