
#include "RevocationManager.h"

#include <iostream>
#include <algorithm>

RevocationManager::RevocationManager()
    : revokedSerialNumbers()
{
}

bool RevocationManager::revokeCertificate(
    const std::string& serialNumber)
{
    // Reject an empty serial number.
    if (serialNumber.empty())
    {
        return false;
    }

    // Prevent the same certificate from being revoked twice.
    if (isRevoked(serialNumber))
    {
        return false;
    }

    revokedSerialNumbers.push_back(serialNumber);
    return true;
}

bool RevocationManager::isRevoked(
    const std::string& serialNumber) const
{
    if (serialNumber.empty())
    {
        return false;
    }

    return std::find(
        revokedSerialNumbers.begin(),
        revokedSerialNumbers.end(),
        serialNumber
    ) != revokedSerialNumbers.end();
}

void RevocationManager::displayRevokedCertificates() const
{
    std::cout << "\n===== REVOKED CERTIFICATES =====\n";

    if (revokedSerialNumbers.empty())
    {
        std::cout << "No certificates have been revoked.\n";
        std::cout << "================================\n";
        return;
    }

    for (const std::string& serialNumber : revokedSerialNumbers)
    {
        std::cout << "Serial Number: " << serialNumber << '\n';
    }

    std::cout << "Total revoked: "
              << revokedSerialNumbers.size() << '\n';

    std::cout << "================================\n";
}
