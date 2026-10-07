#include "RevocationManager.h"
#include <iostream>

RevocationManager::RevocationManager()
{
}

void RevocationManager::revokeCertificate(
    const std::string& serialNumber
)
{
    if(!isRevoked(serialNumber))
    {
        revokedSerialNumbers.push_back(serialNumber);
    }
}

bool RevocationManager::isRevoked(
    const std::string& serialNumber
) const
{
    for(const std::string& revokedSerial : revokedSerialNumbers)
    {
        if(revokedSerial == serialNumber)
        {
            return true;
        }
    }

    return false;
}

void RevocationManager::displayRevokedCertificates() const
{
    std::cout << "----- Revoked Certificates -----"
              << std::endl;

    if(revokedSerialNumbers.empty())
    {
        std::cout << "No revoked certificates."
                  << std::endl;
    }
    else
    {
        for(const std::string& serialNumber :
            revokedSerialNumbers)
        {
            std::cout << "Serial Number: "
                      << serialNumber
                      << std::endl;
        }
    }

    std::cout << "--------------------------------"
              << std::endl;
}