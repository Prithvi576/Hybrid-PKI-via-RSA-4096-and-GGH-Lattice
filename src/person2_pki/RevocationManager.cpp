
#include "RevocationManager.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <string>

namespace
{
    bool normalizeHexSerial(
        const std::string& input,
        std::string& normalized)
    {
        normalized.clear();

        if (input.empty())
        {
            return false;
        }

        for (unsigned char ch : input)
        {
            if (!std::isxdigit(ch))
            {
                return false;
            }

            normalized += static_cast<char>(std::toupper(ch));
        }

        const std::size_t firstNonZero = normalized.find_first_not_of('0');

        if (firstNonZero == std::string::npos)
        {
            normalized = "0";
        }
        else
        {
            normalized.erase(0, firstNonZero);
        }

        return true;
    }
}

RevocationManager::RevocationManager()
    : revokedSerialNumbers()
{
}

bool RevocationManager::revokeCertificate(
    const std::string& serialNumber)
{
    if (serialNumber.empty() || isRevoked(serialNumber))
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

bool RevocationManager::revokeCertificateInFile(
    const std::string& serialNumber,
    const std::string& revocationFilePath) const
{
    std::string normalizedSerial;

    if (revocationFilePath.empty() ||
        !normalizeHexSerial(serialNumber, normalizedSerial))
    {
        return false;
    }

    // Require an existing, readable file. Do not silently create a
    // replacement denylist if the configured file is missing.
    std::ifstream input(revocationFilePath);

    if (!input.is_open())
    {
        return false;
    }

    std::string line;

    while (std::getline(input, line))
    {
        // Ignore blank lines; all nonblank entries must be hex serials.
        if (line.empty())
        {
            continue;
        }

        std::string existingSerial;

        if (!normalizeHexSerial(line, existingSerial))
        {
            return false;
        }

        if (existingSerial == normalizedSerial)
        {
            return false; // Already revoked.
        }
    }

    if (input.bad())
    {
        return false;
    }

    input.close();

    std::ofstream output(
        revocationFilePath,
        std::ios::out | std::ios::app
    );

    if (!output.is_open())
    {
        return false;
    }

    output << normalizedSerial << '\n';
    output.flush();

    return output.good();
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
