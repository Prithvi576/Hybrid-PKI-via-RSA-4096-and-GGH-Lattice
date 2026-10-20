
#include "crypto_api.hpp"

#include <filesystem>
#include <iostream>
#include <string>

int main() {
    const std::string path = "test_ggh_public.key";
    const std::string message = "SCADA GGH key storage test";

    try {
        // 1. Generate a GGH key pair.
        auto original = hybrid_pki::generateGGHKeyPair();

        if (!original.has_private_key() || !original.has_public_key()) {
            std::cerr << "FAIL: GGH key generation\n";
            return 1;
        }
        std::cout << "GGH key generation: PASS\n";

        // 2. Sign a message with the original private key.
        auto signature = hybrid_pki::signGGH(message, original);
        std::cout << "GGH signing: PASS\n";

        // 3. Save only the public key.
        if (!hybrid_pki::saveGGHPublicKey(path, original)) {
            std::cerr << "FAIL: Saving GGH public key\n";
            return 1;
        }
        std::cout << "GGH public-key save: PASS\n";

        // 4. Load the public key.
        auto loaded = hybrid_pki::loadGGHPublicKey(path);

        if (!loaded.has_public_key() || loaded.has_private_key()) {
            std::cerr << "FAIL: Loaded key is not public-only\n";
            return 1;
        }
        std::cout << "GGH public-key load: PASS\n";
        std::cout << "Loaded key has no private key: PASS\n";

        // 5. Compare the public-key fingerprints.
        if (original.public_fingerprint != loaded.public_fingerprint) {
            std::cerr << "FAIL: GGH fingerprint mismatch\n";
            return 1;
        }
        std::cout << "GGH fingerprint match: PASS\n";

        // 6. Verify using the loaded public key only.
        if (!hybrid_pki::verifyGGH(
                message, signature, *loaded.public_key)) {
            std::cerr << "FAIL: GGH verification with loaded key\n";
            return 1;
        }
        std::cout << "Verification with loaded public key: PASS\n";

        std::filesystem::remove(path);
        std::cout << "ALL GGH STORAGE TESTS PASSED\n";
        return 0;
    } catch (const std::exception& e) {
        std::filesystem::remove(path);
        std::cerr << "TEST ERROR: " << e.what() << '\n';
        return 1;
    }
}
