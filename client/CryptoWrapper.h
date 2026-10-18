/**
 * קובץ: CryptoWrapper.h
 * מימוש ההצפנה האסימטרית (RSA-1024) וההצפנה הסימטרית (AES-256-CBC) בצד הלקוח באמצעות ספריית Crypto++
 * (לפי עמוד 4 סעיף ג', עמוד 5, ועמודים 8-9 ו-11 במטלה).
 */

#pragma once

#include "Protocol.h"

#include <osrng.h>
#include <rsa.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Crypto {

    // אורך מפתח ה-RSA הוא 1024 ביט (עמוד 9 במטלה), כך שייצוג X.509 שלו הוא בדיוק 160 בתים (עמוד 11 במטלה)
    constexpr unsigned int RSA_KEY_BITS = 1024;

    using PublicKeyArray = std::array<uint8_t, Protocol::PUBLIC_KEY_SIZE>;
    using AesKeyArray    = std::array<uint8_t, Protocol::AES_KEY_SIZE>;

    // מחלקה המרכזת את פעולות ההצפנה והמפתחות של הלקוח מול Crypto++
    class CryptoWrapper {
    public:
        CryptoWrapper();

        // יצירת זוג מפתחות RSA (ציבורי ופרטי) באורך 1024 ביט בריצה הראשונה (לפי עמוד 5 ועמוד 9)
        void generateRsaKeyPair();

        // קבלת המפתח הציבורי בפורמט X.509 בינארי באורך קבוע של 160 בתים לשליחה בבקשה 826 (לפי עמודים 6 ו-11)
        PublicKeyArray getPublicKeyBytes() const;

        // קידוד המפתח הפרטי לפורמט Base64 לשמירה בקובץ me.info ובקובץ priv.key (לפי עמודים 4-5)
        std::string exportPrivateKeyBase64() const;

        // טעינת המפתח הפרטי מפורמט Base64 בעת התחברות חוזרת (לפי עמוד 5 סעיף 3)
        void loadPrivateKeyBase64(const std::string& base64Key);

        // פתיחת מפתח ה-AES המוצפן שהתקבל מהשרת (בתשובות 1602 או 1605) בעזרת המפתח הפרטי של ה-RSA (עמוד 5)
        AesKeyArray decryptAndStoreAesKey(const uint8_t* encryptedAesData, size_t encryptedSize);
        AesKeyArray decryptAndStoreAesKey(const std::vector<uint8_t>& encryptedAesBuffer);

        // הצפנת תוכן הקובץ בעזרת AES-CBC עם מפתח 256 ביט ו-IV מאופס (16 בתים של אפסים, לפי עמוד 9 במטלה)
        std::vector<uint8_t> encryptFileAesCbc(const uint8_t* plainData, size_t plainSize) const;
        std::vector<uint8_t> encryptFileAesCbc(const std::vector<uint8_t>& plainBuffer) const;

        bool hasRsaKeys() const noexcept;
        bool hasAesKey() const noexcept;

    private:
        mutable CryptoPP::AutoSeededRandomPool m_rng;
        CryptoPP::RSA::PrivateKey              m_privateKey;
        CryptoPP::RSA::PublicKey               m_publicKey;
        bool                                   m_hasRsaKeys;
        AesKeyArray                            m_aesKey;
        bool                                   m_hasAesKey;
    };

} // namespace Crypto
