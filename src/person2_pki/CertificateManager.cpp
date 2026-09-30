#include "CertificateManager.h"
#include <iostream>

CertificateManager::CertificateManager() {
    subject = "";
    issuer = "";
    serialNumber = "";
}

void CertificateManager::setCertificateInfo(
    const std::string& subject,
    const std::string& issuer,
    const std::string& serialNumber
) {
    this->subject = subject;
    this->issuer = issuer;
    this->serialNumber = serialNumber;
}

void CertificateManager::displayCertificateInfo() const {
    std::cout << "----- Certificate Information -----" << std::endl;
    std::cout << "Subject      : " << subject << std::endl;
    std::cout << "Issuer       : " << issuer << std::endl;
    std::cout << "Serial Number: " << serialNumber << std::endl;
    std::cout << "----------------------------------" << std::endl;
}

bool CertificateManager::validateCertificate() const {
    return !subject.empty() &&
           !issuer.empty() &&
           !serialNumber.empty();
}