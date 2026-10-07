#include <iostream>

#include "person2_pki/CertificateManager.h"
#include "person2_pki/PKIManager.h"

int main()
{
    PKIManager pki;

    pki.initialize(
        "SCADA-Root-CA",
        "CA-001"
    );

    CertificateManager certificate =
        pki.issueCertificate(
            "SCADA-PLC-01",
            "SCADA-002"
        );

    certificate.displayCertificateInfo();

    bool valid =
        pki.validateCertificate(
            certificate,
            "SCADA-002"
        );

    if(valid)
    {
        std::cout << "PKI Validation: VALID"
                  << std::endl;
    }
    else
    {
        std::cout << "PKI Validation: INVALID"
                  << std::endl;
    }

    std::cout << std::endl;

    std::cout << "Revoking certificate..."
              << std::endl;

    pki.revokeCertificate(
        "SCADA-002"
    );

    valid =
        pki.validateCertificate(
            certificate,
            "SCADA-002"
        );

    if(valid)
    {
        std::cout << "PKI Validation: VALID"
                  << std::endl;
    }
    else
    {
        std::cout << "PKI Validation: INVALID"
                  << std::endl;
    }

    std::cout << std::endl;

    pki.displayPKIStatus();

    return 0;
}