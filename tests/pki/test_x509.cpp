
#include <iostream>
#include <string>

#include "CertificateValidator.h"

int main()
{
    CertificateValidator validator;
    std::string error;
    int passed = 0;
    int failed = 0;

    auto test = [&](const std::string& name, bool condition)
    {
        if (condition)
        {
            std::cout << "[PASS] " << name << '\n';
            ++passed;
        }
        else
        {
            std::cout << "[FAIL] " << name << '\n';
            if (!error.empty())
            {
                std::cout << "       Reason: " << error << '\n';
            }
            ++failed;
        }

        error.clear();
    };

    // Test 1: Trusted certificate is accepted.
    bool result = validator.validateX509Certificate(
        "test_client.pem",
        "test_ca.pem",
        error
    );

    test("Trusted certificate accepted", result);

    // Test 2: Certificate from an untrusted CA is rejected.
    result = validator.validateX509Certificate(
        "test_client.pem",
        "test_wrong_ca.pem",
        error
    );

    test("Untrusted certificate rejected", !result);

    // Test 3: Missing Key Usage is rejected.
    result = validator.validateX509Certificate(
        "test_no_usage.pem",
        "test_ca.pem",
        error
    );

    test(
        "Certificate without digital-signature Key Usage rejected",
        !result && error.find("Key Usage") != std::string::npos
    );

    // Test 4: A revoked certificate is rejected.
    result = validator.validateX509CertificateWithRevocation(
        "test_client.pem",
        "test_ca.pem",
        "revoked_serials.txt",
        error
    );

    test(
        "Revoked certificate rejected",
        !result && error.find("revoked") != std::string::npos
    );

    // Test 5: A missing revocation file must fail closed.
    result = validator.validateX509CertificateWithRevocation(
        "test_client.pem",
        "test_ca.pem",
        "file_that_does_not_exist.txt",
        error
    );

    test(
        "Missing revocation list rejected",
        !result && error.find("revocation list") != std::string::npos
    );

    std::cout << "\n========== X.509 TEST RESULTS ==========\n";
    std::cout << "Passed: " << passed << '\n';
    std::cout << "Failed: " << failed << '\n';
    std::cout << "Total : " << passed + failed << '\n';
    std::cout << "========================================\n";

    return failed == 0 ? 0 : 1;
}
