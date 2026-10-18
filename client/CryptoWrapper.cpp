/**
 * קובץ: CryptoWrapper.cpp
 * מימוש ההצפנה האסימטרית (RSA-1024) והסימטרית (AES-256-CBC) באמצעות ספריית Crypto++
 * (לפי עמודים 5, 8-9 ו-11 במטלה).
 */

#include "CryptoWrapper.h"

#include <aes.h>
#include <base64.h>
#include <filters.h>
#include <modes.h>
#include <queue.h>

#include <cstring>
#include <stdexcept>

namespace Crypto {

    CryptoWrapper::CryptoWrapper()
        : m_hasRsaKeys(false), m_aesKey{}, m_hasAesKey(false) {}

    // מימוש יצירת זוג מפתחות RSA (ציבורי ופרטי) באורך 1024 ביט (לפי עמוד 5 ועמוד 9 במטלה)
    void CryptoWrapper::generateRsaKeyPair() {
        m_privateKey.Initialize(m_rng, RSA_KEY_BITS);
        m_publicKey.AssignFrom(m_privateKey);
        m_hasRsaKeys = true;
    }

    // מימוש ייצוא המפתח הציבורי בפורמט X.509 באורך 160 בתים בדיוק (לפי ההערה בעמוד 11 וטבלת 826 בעמוד 6)
    PublicKeyArray CryptoWrapper::getPublicKeyBytes() const {
        if (!m_hasRsaKeys) {
            throw std::runtime_error("RSA key pair is not initialized.");
        }

        PublicKeyArray pubKeyBytes{};
        CryptoPP::ArraySink sink(pubKeyBytes.data(), pubKeyBytes.size());
        m_publicKey.Save(sink);

        if (sink.TotalPutLength() != Protocol::PUBLIC_KEY_SIZE) {
            throw std::runtime_error(
                "Unexpected X.509 RSA public key size: " + std::to_string(sink.TotalPutLength())
            );
        }

        return pubKeyBytes;
    }

    // מימוש קידוד המפתח הפרטי לפורמט Base64 עבור השורה השלישית בקובץ me.info והקובץ priv.key (עמודים 4-5)
    std::string CryptoWrapper::exportPrivateKeyBase64() const {
        if (!m_hasRsaKeys) {
            throw std::runtime_error("RSA key pair is not initialized.");
        }

        std::string base64Key;
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(base64Key), false);
        m_privateKey.DEREncode(encoder);
        encoder.MessageEnd();

        return base64Key;
    }

    // מימוש טעינת המפתח הפרטי מפורמט Base64 לשימוש חוזר בהתחברות חוזרת (לפי עמוד 5 סעיף 3)
    void CryptoWrapper::loadPrivateKeyBase64(const std::string& base64Key) {
        if (base64Key.empty()) {
            throw std::invalid_argument("Private key Base64 string is empty.");
        }

        try {
            CryptoPP::ByteQueue queue;
            CryptoPP::StringSource source(
                base64Key,
                true,
                new CryptoPP::Base64Decoder(new CryptoPP::Redirector(queue))
            );

            m_privateKey.BERDecode(queue);
            m_publicKey.AssignFrom(m_privateKey);
            m_hasRsaKeys = true;
        } catch (const CryptoPP::Exception& ex) {
            throw std::runtime_error(std::string("Failed loading RSA private key: ") + ex.what());
        }
    }

    // מימוש פתיחת מפתח ה-AES המוצפן שהתקבל מהשרת בעזרת המפתח הפרטי של ה-RSA (לפי עמוד 5 במטלה)
    AesKeyArray CryptoWrapper::decryptAndStoreAesKey(const uint8_t* encryptedAesData, size_t encryptedSize) {
        if (!m_hasRsaKeys) {
            throw std::runtime_error("RSA private key is not loaded.");
        }
        if (encryptedAesData == nullptr || encryptedSize == 0) {
            throw std::invalid_argument("Encrypted AES key buffer is empty.");
        }

        try {
            std::string decrypted;
            CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(m_privateKey);

            CryptoPP::ArraySource source(
                encryptedAesData,
                encryptedSize,
                true,
                new CryptoPP::PK_DecryptorFilter(m_rng, decryptor, new CryptoPP::StringSink(decrypted))
            );

            if (decrypted.size() != Protocol::AES_KEY_SIZE) {
                throw std::runtime_error("Decrypted AES key is not 32 bytes (256-bit).");
            }

            std::memcpy(m_aesKey.data(), decrypted.data(), Protocol::AES_KEY_SIZE);
            m_hasAesKey = true;
            return m_aesKey;
        } catch (const CryptoPP::Exception& ex) {
            throw std::runtime_error(std::string("Failed decrypting AES key: ") + ex.what());
        }
    }

    AesKeyArray CryptoWrapper::decryptAndStoreAesKey(const std::vector<uint8_t>& encryptedAesBuffer) {
        return decryptAndStoreAesKey(encryptedAesBuffer.data(), encryptedAesBuffer.size());
    }

    // מימוש הצפנת הקובץ בעזרת AES-CBC באורך מפתח של 256 ביט ו-IV מאופס תמיד (לפי עמוד 9 במטלה)
    std::vector<uint8_t> CryptoWrapper::encryptFileAesCbc(const uint8_t* plainData, size_t plainSize) const {
        if (!m_hasAesKey) {
            throw std::runtime_error("AES key is not initialized.");
        }

        try {
            // לפי עמוד 9 במטלה: ניתן להניח שה-IV מאופס תמיד (הזיכרון מלא באפסים - 16 בתים)
            uint8_t zeroIv[Protocol::AES_BLOCK_SIZE] = { 0 };

            CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aesEncryption(
                m_aesKey.data(),
                m_aesKey.size(),
                zeroIv
            );

            std::string cipherText;
            CryptoPP::ArraySource source(
                plainData,
                plainSize,
                true,
                new CryptoPP::StreamTransformationFilter(
                    aesEncryption,
                    new CryptoPP::StringSink(cipherText),
                    CryptoPP::StreamTransformationFilter::PKCS_PADDING
                )
            );

            return std::vector<uint8_t>(cipherText.begin(), cipherText.end());
        } catch (const CryptoPP::Exception& ex) {
            throw std::runtime_error(std::string("AES-CBC encryption failed: ") + ex.what());
        }
    }

    std::vector<uint8_t> CryptoWrapper::encryptFileAesCbc(const std::vector<uint8_t>& plainBuffer) const {
        return encryptFileAesCbc(plainBuffer.data(), plainBuffer.size());
    }

    bool CryptoWrapper::hasRsaKeys() const noexcept {
        return m_hasRsaKeys;
    }

    bool CryptoWrapper::hasAesKey() const noexcept {
        return m_hasAesKey;
    }

} // namespace Crypto
