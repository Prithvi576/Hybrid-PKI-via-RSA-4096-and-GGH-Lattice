#include <iostream>
#include "person2_pki/CertificateManager.h"
#include "person2_pki/PKIManager.h"

int main()
{
    PKIManager pki;
    pki.initialize("SCADA-Root-CA", "CA-001");

    std::cout << "\n=== TEST 1: Issue Certificate ===\n";
    CertificateManager certificate =
        pki.issueCertificate("SCADA-PLC-01", "SCADA-002");

    certificate.displayCertificateInfo();

    std::cout << "\n=== TEST 2: Validate Correct Serial ===\n";
    bool valid = pki.validateCertificate(certificate, "SCADA-002");
    std::cout << (valid
        ? "PASS: Certificate VALID\n"
        : "FAIL: Certificate should be VALID\n");

    std::cout << "\n=== TEST 3: Validate Incorrect Serial ===\n";
    bool wrongSerialValid =
        pki.validateCertificate(certificate, "SCADA-999");

    std::cout << (!wrongSerialValid
        ? "PASS: Incorrect serial REJECTED\n"
        : "FAIL: Incorrect serial was accepted\n");

    std::cout << "\n=== TEST 4: Revoke Certificate ===\n";
    pki.revokeCertificate("SCADA-002");

    valid = pki.validateCertificate(certificate, "SCADA-002");

    std::cout << (!valid
        ? "PASS: Revoked certificate REJECTED\n"
        : "FAIL: Revoked certificate was accepted\n");

    std::cout << "\n=== TEST 5: Repeated Revocation ===\n";
    pki.revokeCertificate("SCADA-002");

    valid = pki.validateCertificate(certificate, "SCADA-002");

    std::cout << (!valid
        ? "PASS: Certificate remains INVALID\n"
        : "FAIL: Revoked certificate became valid\n");

    std::cout << "\n=== FINAL PKI STATUS ===\n";
    pki.displayPKIStatus();

    return 0;
    }