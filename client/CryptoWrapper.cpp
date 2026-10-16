/**
 * @file CryptoWrapper.cpp
 * @brief מימוש מחלקת העטיפה (`CryptoWrapper`) לספריית `Crypto++` (`cryptlib.lib`).
 *
 * קובץ זה מממש את הפעולות הקריפטוגרפיות בצד הלקוח:
 * - יצירת זוג מפתחות RSA באורך 1024 ביט (`generateRsaKeyPair`).
 * - ייצוא המפתח הציבורי בפורמט X.509 בינארי באורך בדיוק 160 בתים (`getPublicKeyBytes` באמצעות `Save`).
 * - ייצוא וייבוא של המפתח הפרטי בפורמט Base64 (`exportPrivateKeyBase64`, `loadPrivateKeyBase64` באמצעות `Base64Encoder` ו-`Base64Decoder`).
 * - פענוח מפתח ה-AES המוצפן מהשרת באמצעות `CryptoPP::RSAES_OAEP_SHA_Decryptor` (`decryptAndStoreAesKey`).
 * - הצפנת תוכן קובץ ב-`AES-CBC` עם מפתח 256 ביט (32 בתים) ו-`IV` מאופס בן 16 בתים (`encryptFileAesCbc`).
 *
 * מי קורא למודול זה:
 * - מחלקת הלקוח הראשית בעת רישום מפתח ציבורי (826), התחברות חוזרת (827), והצפנת קבצים (828).
 */

#include "CryptoWrapper.h"

// כותרות ספריית Crypto++
#include <aes.h>
#include <base64.h>
#include <filters.h>
#include <modes.h>
#include <queue.h>

#include <cstring>
#include <stdexcept>

namespace Crypto {

    /**
     * @brief בנאי המחלקה - מאתחל את הדגלים ומאפס את מערך מפתח ה-AES.
     */
    CryptoWrapper::CryptoWrapper()
        : m_hasRsaKeys(false), m_aesKey{}, m_hasAesKey(false) {}

    /**
     * @brief יצירת זוג מפתחות RSA חדש (פרטי וציבורי) באורך 1024 ביט.
     */
    void CryptoWrapper::generateRsaKeyPair() {
        m_privateKey.Initialize(m_rng, RSA_KEY_BITS);
        if (!m_privateKey.Validate(m_rng, 3)) {
            throw std::runtime_error("Generated RSA private key failed Crypto++ validation.");
        }

        // גזירת המפתח הציבורי מתוך המפתח הפרטי
        m_publicKey.AssignFrom(m_privateKey);
        if (!m_publicKey.Validate(m_rng, 3)) {
            throw std::runtime_error("Generated RSA public key failed Crypto++ validation.");
        }

        m_hasRsaKeys = true;
    }

    /**
     * @brief ייצוא המפתח הציבורי בפורמט X.509 בינארי באורך בדיוק 160 בתים (`PUBLIC_KEY_SIZE`).
     *        הערה מהמטלה: ספריית Crypto++ שומרת מפתחות ציבוריים של RSA-1024 בפורמט X.509 באורך סופי של 160 בתים.
     */
    PublicKeyArray CryptoWrapper::getPublicKeyBytes() const {
        if (!m_hasRsaKeys) {
            throw std::runtime_error("Cannot export RSA public key: RSA key pair has not been initialized.");
        }

        PublicKeyArray pubKeyBytes{};
        CryptoPP::ArraySink sink(pubKeyBytes.data(), pubKeyBytes.size());
        m_publicKey.Save(sink);

        if (sink.TotalPutLength() != Protocol::PUBLIC_KEY_SIZE) {
            throw std::runtime_error(
                "Exported X.509 RSA public key size mismatch: expected 160 bytes, got " +
                std::to_string(sink.TotalPutLength())
            );
        }

        return pubKeyBytes;
    }

    /**
     * @brief ייצוא המפתח הפרטי של ה-RSA למחרוזת Base64 (ללא תווי ירידת שורה, לשמירה ב-`me.info` וב-`priv.key`).
     */
    std::string CryptoWrapper::exportPrivateKeyBase64() const {
        if (!m_hasRsaKeys) {
            throw std::runtime_error("Cannot export RSA private key: RSA key pair has not been initialized.");
        }

        std::string base64Key;
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(base64Key), false /* ללא ירידות שורה */);
        m_privateKey.DEREncode(encoder);
        encoder.MessageEnd();

        return base64Key;
    }

    /**
     * @brief ייבוא המפתח הפרטי של ה-RSA מתוך מחרוזת Base64 וגזירת המפתח הציבורי התואם.
     */
    void CryptoWrapper::loadPrivateKeyBase64(const std::string& base64Key) {
        if (base64Key.empty()) {
            throw std::invalid_argument("Cannot load RSA private key from an empty Base64 string.");
        }

        try {
            CryptoPP::ByteQueue queue;
            CryptoPP::StringSource source(
                base64Key,
                true,
                new CryptoPP::Base64Decoder(new CryptoPP::Redirector(queue))
            );

            m_privateKey.BERDecode(queue);
            if (!m_privateKey.Validate(m_rng, 3)) {
                throw std::runtime_error("Loaded RSA private key failed Crypto++ validation.");
            }

            m_publicKey.AssignFrom(m_privateKey);
            m_hasRsaKeys = true;
        } catch (const CryptoPP::Exception& ex) {
            throw std::runtime_error(std::string("Crypto++ error while loading RSA private key: ") + ex.what());
        }
    }

    /**
     * @brief פענוח מפתח ה-AES המוצפן שהתקבל מהשרת באמצעות `RSAES_OAEP_SHA_Decryptor` ושמירתו במחלקה.
     */
    AesKeyArray CryptoWrapper::decryptAndStoreAesKey(const uint8_t* encryptedAesData, size_t encryptedSize) {
        if (!m_hasRsaKeys) {
            throw std::runtime_error("Cannot decrypt AES key: RSA private key is not loaded.");
        }
        if (encryptedAesData == nullptr || encryptedSize == 0) {
            throw std::invalid_argument("Encrypted AES key buffer is empty or null.");
        }

        try {
            std::string decryptedStr;
            CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(m_privateKey);

            CryptoPP::ArraySource source(
                encryptedAesData,
                encryptedSize,
                true,
                new CryptoPP::PK_DecryptorFilter(m_rng, decryptor, new CryptoPP::StringSink(decryptedStr))
            );

            if (decryptedStr.size() != Protocol::AES_KEY_SIZE) {
                throw std::runtime_error(
                    "Decrypted AES key size mismatch: expected 32 bytes (256-bit), got " +
                    std::to_string(decryptedStr.size())
                );
            }

            std::memcpy(m_aesKey.data(), decryptedStr.data(), Protocol::AES_KEY_SIZE);
            m_hasAesKey = true;
            return m_aesKey;
        } catch (const CryptoPP::Exception& ex) {
            throw std::runtime_error(std::string("Crypto++ error while decrypting AES key: ") + ex.what());
        }
    }

    /**
     * @brief מעטפת נוחה לפענוח ושמירת מפתח ה-AES מתוך וקטור בתים.
     */
    AesKeyArray CryptoWrapper::decryptAndStoreAesKey(const std::vector<uint8_t>& encryptedAesBuffer) {
        return decryptAndStoreAesKey(encryptedAesBuffer.data(), encryptedAesBuffer.size());
    }

    /**
     * @brief הצפנת תוכן קובץ באמצעות `AES-CBC` עם מפתח 256 ביט ו-`IV` מאופס בן 16 בתים.
     */
    std::vector<uint8_t> CryptoWrapper::encryptFileAesCbc(const uint8_t* plainData, size_t plainSize) const {
        if (!m_hasAesKey) {
            throw std::runtime_error("Cannot encrypt file: AES key has not been received/decrypted yet.");
        }
        if (plainSize > 0 && plainData == nullptr) {
            throw std::invalid_argument("Plain file data pointer is null with non-zero size.");
        }

        try {
            // וקטור אתחול (IV) מאופס תמיד (16 בתים של אפסים) כנדרש במפרט המטלה (עמוד 9)
            uint8_t zeroIv[Protocol::AES_BLOCK_SIZE] = { 0 };

            CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aesEncryption(
                m_aesKey.data(),
                m_aesKey.size(),
                zeroIv
            );

            std::string cipherStr;
            CryptoPP::ArraySource source(
                plainData,
                plainSize,
                true,
                new CryptoPP::StreamTransformationFilter(
                    aesEncryption,
                    new CryptoPP::StringSink(cipherStr),
                    CryptoPP::StreamTransformationFilter::PKCS_PADDING
                )
            );

            return std::vector<uint8_t>(cipherStr.begin(), cipherStr.end());
        } catch (const CryptoPP::Exception& ex) {
            throw std::runtime_error(std::string("Crypto++ error during AES-CBC file encryption: ") + ex.what());
        }
    }

    /**
     * @brief מעטפת נוחה להצפנת וקטור בתים של קובץ באמצעות `AES-CBC`.
     */
    std::vector<uint8_t> CryptoWrapper::encryptFileAesCbc(const std::vector<uint8_t>& plainBuffer) const {
        return encryptFileAesCbc(plainBuffer.data(), plainBuffer.size());
    }

    /**
     * @brief בדיקה האם קיים זוג מפתחות RSA תקין במופע זה.
     */
    bool CryptoWrapper::hasRsaKeys() const noexcept {
        return m_hasRsaKeys;
    }

    /**
     * @brief בדיקה האם קיים מפתח AES פעיל במופע זה.
     */
    bool CryptoWrapper::hasAesKey() const noexcept {
        return m_hasAesKey;
    }

} // namespace Crypto

