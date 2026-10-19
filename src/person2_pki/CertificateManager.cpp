#include "CertificateManager.h"
#include <iostream>

CertificateManager::CertificateManager()
    : subject(), issuer(), serialNumber()
{
}

void CertificateManager::setCertificateInfo(
    const std::string& subjectValue,
    const std::string& issuerValue,
    const std::string& serialNumberValue)
{
    subject = subjectValue;
    issuer = issuerValue;
    serialNumber = serialNumberValue;
}

void CertificateManager::displayCertificateInfo() const
{
    std::cout << "----- Certificate Information -----\n"
              << "Subject      : " << subject << '\n'
              << "Issuer       : " << issuer << '\n'
              << "Serial Number: " << serialNumber << '\n'
              << "-----------------------------------\n";
}

bool CertificateManager::validateCertificate() const
{
    return !subject.empty() && !issuer.empty() && !serialNumber.empty();
}

std::string CertificateManager::getCertificateSummary() const
{
    return "Subject: " + subject +
           "\nIssuer: " + issuer +
           "\nSerial Number: " + serialNumber;
}

const std::string& CertificateManager::getSubject() const
{
    return subject;
}

const std::string& CertificateManager::getIssuer() const
{
    return issuer;
}

const std::string& CertificateManager::getSerialNumber() const
{
    return serialNumber;
}
