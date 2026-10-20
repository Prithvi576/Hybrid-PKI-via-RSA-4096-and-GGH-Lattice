
#include "crypto_api.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace hybrid_pki {

namespace {

std::string rsaStorageError(const char* context) {
    const unsigned long code = ERR_get_error();

    if (code == 0) {
        return std::string(context) + " failed";
    }

    char message[256]{};
    ERR_error_string_n(code, message, sizeof(message));
    return std::string(context) + ": " + message;
}

} // namespace

bool saveRSAPublicKey(
    const std::string& file_path,
    const RSAKeyPair& key_pair) {

    if (file_path.empty() || !key_pair.has_public_key()) {
        return false;
    }

    auto* key = static_cast<EVP_PKEY*>(
        key_pair.public_handle.get());

    if (key == nullptr) {
        return false;
    }

    BIO* raw_bio = BIO_new_file(file_path.c_str(), "w");
    if (raw_bio == nullptr) {
        return false;
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        raw_bio, BIO_free);

    return PEM_write_bio_PUBKEY(bio.get(), key) == 1;
}

RSAKeyPair loadRSAPublicKey(const std::string& file_path) {
    if (file_path.empty()) {
        throw std::invalid_argument("RSA public-key path is empty");
    }

    BIO* raw_bio = BIO_new_file(file_path.c_str(), "r");
    if (raw_bio == nullptr) {
        throw std::runtime_error(
            rsaStorageError("Opening RSA public-key file"));
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        raw_bio, BIO_free);

    EVP_PKEY* raw_key = PEM_read_bio_PUBKEY(
        bio.get(), nullptr, nullptr, nullptr);

    if (raw_key == nullptr) {
        throw std::runtime_error(
            rsaStorageError("Reading RSA public key"));
    }

    std::shared_ptr<void> public_key(
        raw_key,
        [](void* value) {
            EVP_PKEY_free(static_cast<EVP_PKEY*>(value));
        });

    RSAKeyPair result;
    result.private_handle.reset();
    result.public_handle = std::move(public_key);

    unsigned char* der = nullptr;
    const int der_length = i2d_PUBKEY(raw_key, &der);

    if (der_length <= 0 || der == nullptr) {
        throw std::runtime_error(
            rsaStorageError("Encoding loaded RSA public key"));
    }

    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int digest_length = 0;

    const int digest_ok = EVP_Digest(
        der,
        static_cast<size_t>(der_length),
        digest,
        &digest_length,
        EVP_sha256(),
        nullptr);

    OPENSSL_free(der);

    if (digest_ok != 1) {
        throw std::runtime_error(
            rsaStorageError("Fingerprinting loaded RSA public key"));
    }

    static const char hex[] = "0123456789abcdef";
    result.public_fingerprint.clear();

    for (unsigned int i = 0; i < 10 && i < digest_length; ++i) {
        result.public_fingerprint += hex[digest[i] >> 4];
        result.public_fingerprint += hex[digest[i] & 0x0f];
    }

    return result;
}

} // namespace hybrid_pki
