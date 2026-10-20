
#include "crypto_api.hpp"

#include <filesystem>
#include <iostream>
#include <string>

int main() {
    const std::string path = "test_rsa_public.pem";
    const std::string message = "SCADA RSA storage test";

    try {
        // Generate the original RSA key pair.
        auto original = hybrid_pki::generateRSAKeyPair();

        if (!original.has_private_key() || !original.has_public_key()) {
            std::cerr << "FAIL: RSA key generation\n";
            return 1;
        }
        std::cout << "RSA key generation: PASS\n";

        // Save the public key.
        if (!hybrid_pki::saveRSAPublicKey(path, original)) {
            std::cerr << "FAIL: Saving public key\n";
            return 1;
        }
        std::cout << "RSA public-key save: PASS\n";

        // Load the public key without the private key.
        auto loaded = hybrid_pki::loadRSAPublicKey(path);

        if (!loaded.has_public_key() || loaded.has_private_key()) {
            std::cerr << "FAIL: Loaded key is not public-only\n";
            return 1;
        }
        std::cout << "RSA public-key load: PASS\n";
        std::cout << "Loaded key has no private key: PASS\n";

        // The public fingerprint should remain the same.
        if (original.public_fingerprint != loaded.public_fingerprint) {
            std::cerr << "FAIL: Fingerprint mismatch\n";
            return 1;
        }
        std::cout << "Fingerprint match: PASS\n";

        // Sign with the original key and verify with the loaded key.
        auto signature = hybrid_pki::signRSA(message, original);

        if (!hybrid_pki::verifyRSA(message, signature, loaded)) {
            std::cerr << "FAIL: Signature verification\n";
            return 1;
        }
        std::cout << "Signature verification: PASS\n";

        std::filesystem::remove(path);
        std::cout << "ALL RSA STORAGE TESTS PASSED\n";
        return 0;
    } catch (const std::exception& e) {
        std::filesystem::remove(path);
        std::cerr << "TEST ERROR: " << e.what() << '\n';
        return 1;
    }
}
