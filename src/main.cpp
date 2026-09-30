#include <iostream>
#include "person2_pki/CertificateManager.h"

int main() {

    CertificateManager manager;

    manager.setCertificateInfo(
        "SCADA-Control-Center",
        "SCADA-Root-CA",
        "SCADA-001"
    );

    manager.displayCertificateInfo();

    if (manager.validateCertificate()) {
        std::cout << "Certificate Status: VALID" << std::endl;
    } else {
        std::cout << "Certificate Status: INVALID" << std::endl;
    }

    return 0;
}