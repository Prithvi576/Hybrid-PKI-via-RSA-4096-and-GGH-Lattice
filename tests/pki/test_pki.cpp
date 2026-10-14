
#include <iostream>
#include <stdexcept>
#include <string>

#include "PKIManager.h"

using namespace std;

int passed = 0;
int failed = 0;

void test(const string& testName, bool condition)
{
    if (condition)
    {
        cout << "[PASS] " << testName << '\n';
        passed++;
    }
    else
    {
        cout << "[FAIL] " << testName << '\n';
        failed++;
    }
}

int main()
{
    // ==========================================
    // TEST GROUP 1: INITIALIZATION
    // ==========================================

    PKIManager pki;
    bool initializationSucceeded = true;

    try
    {
        pki.initialize("SCADA Root CA", "SCADA-CA-001");
    }
    catch (...)
    {
        initializationSucceeded = false;
    }

    test("PKI initializes successfully", initializationSucceeded);

    PKIManager emptyNamePKI;
    bool emptyNameRejected = false;

    try
    {
        emptyNamePKI.initialize("", "SCADA-CA-002");
    }
    catch (const invalid_argument&)
    {
        emptyNameRejected = true;
    }

    test("Empty CA name is rejected", emptyNameRejected);

    PKIManager emptyIdentifierPKI;
    bool emptyIdentifierRejected = false;

    try
    {
        emptyIdentifierPKI.initialize("SCADA Root CA", "");
    }
    catch (const invalid_argument&)
    {
        emptyIdentifierRejected = true;
    }

    test("Empty CA identifier is rejected", emptyIdentifierRejected);

    bool issuanceBeforeInitializationRejected = false;

    try
    {
        emptyNamePKI.issueCertificate(
            "SCADA-DEVICE-INVALID",
            "SCADA-INVALID-001"
        );
    }
    catch (const logic_error&)
    {
        issuanceBeforeInitializationRejected = true;
    }

    test(
        "Failed initialization leaves PKI uninitialized",
        issuanceBeforeInitializationRejected
    );

    bool reinitializationRejected = false;

    try
    {
        pki.initialize("Replacement CA", "SCADA-CA-999");
    }
    catch (const logic_error&)
    {
        reinitializationRejected = true;
    }

    test(
        "Repeated PKI initialization is rejected",
        reinitializationRejected
    );

    // ==========================================
    // TEST GROUP 2: CERTIFICATE ISSUANCE
    // ==========================================

    CertificateManager certificate;
    bool issuanceSucceeded = true;

    try
    {
        certificate = pki.issueCertificate(
            "SCADA-DEVICE-001",
            "SCADA-TEST-001"
        );
    }
    catch (...)
    {
        issuanceSucceeded = false;
    }

    test("Certificate issuance succeeds", issuanceSucceeded);

    bool emptySubjectRejected = false;

    try
    {
        pki.issueCertificate("", "SCADA-TEST-EMPTY-SUBJECT");
    }
    catch (const invalid_argument&)
    {
        emptySubjectRejected = true;
    }

    test("Empty certificate subject is rejected", emptySubjectRejected);

    bool emptySerialRejected = false;

    try
    {
        pki.issueCertificate("SCADA-DEVICE-EMPTY-SERIAL", "");
    }
    catch (const invalid_argument&)
    {
        emptySerialRejected = true;
    }

    test("Empty certificate serial number is rejected", emptySerialRejected);

    // ==========================================
    // TEST GROUP 3: CERTIFICATE VALIDATION
    // ==========================================

    test(
        "Newly issued certificate validates",
        pki.validateCertificate(certificate, "SCADA-TEST-001")
    );

    test(
        "Incorrect serial number is rejected",
        !pki.validateCertificate(certificate, "WRONG-SERIAL")
    );

    test(
        "Empty expected serial is rejected",
        !pki.validateCertificate(certificate, "")
    );

    CertificateManager modifiedSubject;
    modifiedSubject.setCertificateInfo(
        "SCADA-DEVICE-TAMPERED",
        "SCADA Root CA",
        "SCADA-TEST-001"
    );

    test(
        "Modified subject is rejected",
        !pki.validateCertificate(modifiedSubject, "SCADA-TEST-001")
    );

    CertificateManager wrongIssuer;
    wrongIssuer.setCertificateInfo(
        "SCADA-DEVICE-001",
        "Untrusted CA",
        "SCADA-TEST-001"
    );

    test(
        "Certificate from an untrusted issuer is rejected",
        !pki.validateCertificate(wrongIssuer, "SCADA-TEST-001")
    );

    PKIManager uninitializedPKI;

    test(
        "Uninitialized PKI cannot validate certificates",
        !uninitializedPKI.validateCertificate(
            certificate,
            "SCADA-TEST-001"
        )
    );

    // ==========================================
    // TEST GROUP 4: SERIAL NUMBER UNIQUENESS
    // ==========================================

    bool duplicateRejected = false;

    try
    {
        pki.issueCertificate(
            "SCADA-DEVICE-002",
            "SCADA-TEST-001"
        );
    }
    catch (const invalid_argument&)
    {
        duplicateRejected = true;
    }

    test("Duplicate serial number is rejected", duplicateRejected);

    // ==========================================
    // TEST GROUP 5: CERTIFICATE REVOCATION
    // ==========================================

    test(
        "Empty serial number cannot be revoked",
        !pki.revokeCertificate("")
    );

    test(
        "Unknown certificate cannot be revoked",
        !pki.revokeCertificate("UNKNOWN-SERIAL")
    );

    test(
        "First revocation succeeds",
        pki.revokeCertificate("SCADA-TEST-001")
    );

    test(
        "Revoked certificate stays invalid",
        !pki.validateCertificate(certificate, "SCADA-TEST-001")
    );

    test(
        "Repeated revocation is rejected",
        !pki.revokeCertificate("SCADA-TEST-001")
    );

    // ==========================================
    // TEST GROUP 6: INDEPENDENT CERTIFICATES
    // ==========================================

    CertificateManager secondCertificate;
    bool secondIssuanceSucceeded = true;

    try
    {
        secondCertificate = pki.issueCertificate(
            "SCADA-DEVICE-002",
            "SCADA-TEST-002"
        );
    }
    catch (...)
    {
        secondIssuanceSucceeded = false;
    }

    test("Second certificate can be issued", secondIssuanceSucceeded);

    test(
        "Another issued certificate remains valid",
        secondIssuanceSucceeded &&
        pki.validateCertificate(
            secondCertificate,
            "SCADA-TEST-002"
        )
    );

    test(
        "Revoking one certificate does not revoke another",
        secondIssuanceSucceeded &&
        !pki.revokeCertificate("SCADA-TEST-001") &&
        pki.validateCertificate(
            secondCertificate,
            "SCADA-TEST-002"
        )
    );

    // ==========================================
    // FINAL RESULTS
    // ==========================================

    cout << "\n========== PKI TEST RESULTS ==========\n";
    cout << "Passed: " << passed << '\n';
    cout << "Failed: " << failed << '\n';
    cout << "Total : " << passed + failed << '\n';
    cout << "======================================\n";

    return failed == 0 ? 0 : 1;
}
