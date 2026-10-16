/**
 * @file CryptoWrapper.h
 * @brief הצהרת מחלקת העטיפה (`CryptoWrapper`) לספריית ההצפנה `Crypto++` (`cryptlib.lib`).
 *
 * מחלקה זו מרכזת את כל הפעולות הקריפטוגרפיות של צד הלקוח לפי דרישות המטלה:
 * 1. יצירת זוג מפתחות RSA אסימטריים באורך 1024 ביט (`RSA_KEY_BITS = 1024`).
 * 2. ייצוא המפתח הציבורי בפורמט X.509 (`SubjectPublicKeyInfo`) בינארי באורך קבוע של 160 בתים (`PUBLIC_KEY_SIZE`).
 * 3. ייצוא וייבוא של המפתח הפרטי בפורמט Base64 לצורך שמירה וטעינה מקובצי `me.info` ו-`priv.key`.
 * 4. פענוח מפתח ה-AES הסימטרי המוצפן שהתקבל מהשרת (בתשובות 1602 או 1605) באמצעות המפתח הפרטי של ה-RSA
 *    בשיטת `CryptoPP::RSAES_OAEP_SHA_Decryptor` (תואם ל-`PKCS1_OAEP` בשרת הפייתון).
 * 5. הצפנת תוכן קובץ באמצעות `AES-CBC` עם מפתח באורך 256 ביט (32 בתים) ווקטור אתחול (`IV`) מאופס
 *    (16 בתים של אפסים) וריפוד PKCS#7 סטנדרטי של Crypto++.
 *
 * מי קורא למודול זה:
 * - מחלקת הלקוח הראשית (`Client`) בתהליכי הרישום והחלפת המפתחות (בקשה 826, תשובה 1602),
 *   בהתחברות חוזרת (תשובה 1605), ובהצפנת הקבצים לפני שליחתם (בקשה 828).
 */

#pragma once

#include "Protocol.h"

// כותרות ספריית Crypto++
#include <rsa.h>
#include <osrng.h>

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace Crypto {

    /// אורך מפתח ה-RSA בביטים כנדרש במפרט המטלה (1024 ביט -> מפתח ציבורי X.509 באורך 160 בתים)
    constexpr unsigned int RSA_KEY_BITS = 1024;

    /// טיפוס עזר למפתח הציבורי הבינארי (160 בתים)
    using PublicKeyArray = std::array<uint8_t, Protocol::PUBLIC_KEY_SIZE>;

    /// טיפוס עזר למפתח ה-AES הסימטרי (32 בתים / 256 ביט)
    using AesKeyArray = std::array<uint8_t, Protocol::AES_KEY_SIZE>;

    /**
     * @class CryptoWrapper
     * @brief מחלקת עטיפה המנהלת את מפתחות ה-RSA וה-AES של הלקוח ומבצעת הצפנה ופענוח מול `Crypto++`.
     *
     * שדות פרטיים מרכזיים:
     * - `m_rng`: מחולל מספרים אקראיים קריפטוגרפי של מערכת ההפעלה (`CryptoPP::AutoSeededRandomPool`).
     * - `m_privateKey`: המפתח הפרטי של הלקוח (`CryptoPP::RSA::PrivateKey`).
     * - `m_publicKey`: המפתח הציבורי של הלקוח (`CryptoPP::RSA::PublicKey`).
     * - `m_hasRsaKeys`: דגל המציין האם זוג מפתחות ה-RSA אותחל או נטען בהצלחה.
     * - `m_aesKey`: מפתח ה-AES הסימטרי (32 בתים) שהתקבל מהשרת ופוענח.
     * - `m_hasAesKey`: דגל המציין האם מפתח ה-AES קיים ומוכן להצפנת קבצים.
     */
    class CryptoWrapper {
    public:
        /**
         * @brief בנאי ברירת מחדל - מאתחל את מחולל המספרים האקראיים ואת דגלי המפתחות.
         */
        CryptoWrapper();

        /**
         * @brief יצירת זוג מפתחות RSA חדש (פרטי וציבורי) באורך 1024 ביט.
         *        נקראת ברישום ראשוני של לקוח חדש (לפני שליחת בקשה 826) או אם התבקש רישום מחדש לאחר קוד 1606.
         */
        void generateRsaKeyPair();

        /**
         * @brief ייצוא המפתח הציבורי של ה-RSA בפורמט X.509 בינארי באורך בדיוק 160 בתים (`PUBLIC_KEY_SIZE`).
         *        זורקת חריגת `std::runtime_error` אם המפתחות טרם נוצרו או אם הגודל אינו 160 בתים.
         *
         * @return מערך בן 160 בתים המוכן להצבה בשדה `publicKey` של בקשה 826.
         */
        PublicKeyArray getPublicKeyBytes() const;

        /**
         * @brief ייצוא המפתח הפרטי של ה-RSA למחרוזת בפורמט Base64 (ללא ירידות שורה מיותרות).
         *        משמש לשמירת המפתח הפרטי בקובץ `me.info` (שורה 3) ובקובץ `priv.key`.
         *
         * @return מחרוזת Base64 של המפתח הפרטי.
         */
        std::string exportPrivateKeyBase64() const;

        /**
         * @brief טעינת (ייבוא) המפתח הפרטי של ה-RSA מתוך מחרוזת Base64 וגזירת המפתח הציבורי התואם ממנו.
         *        נקראת בעת התחברות חוזרת (קוד 827) כאשר טוענים את המפתח מתוך `priv.key` או `me.info`.
         *        זורקת חריגת `std::runtime_error` אם המפתח אינו תקין.
         *
         * @param base64Key מחרוזת ה-Base64 של המפתח הפרטי.
         */
        void loadPrivateKeyBase64(const std::string& base64Key);

        /**
         * @brief פענוח מפתח ה-AES המוצפן שהתקבל מהשרת (בתשובות 1602 או 1605) באמצעות המפתח הפרטי של ה-RSA
         *        בשיטת `RSAES_OAEP_SHA_Decryptor`, ושמירת מפתח ה-AES (32 בתים) בתוך המחלקה.
         *        זורקת חריגת `std::runtime_error` אם הפענוח נכשל או אם אורך המפתח המפוענח אינו 32 בתים.
         *
         * @param encryptedAesData מצביע לבתי מפתח ה-AES המוצפן שהתקבלו מהשרת.
         * @param encryptedSize אורך המפתח המוצפן בבתים (128 בתים עבור RSA-1024).
         * @return מערך 32 הבתים של מפתח ה-AES המפוענח.
         */
        AesKeyArray decryptAndStoreAesKey(const uint8_t* encryptedAesData, size_t encryptedSize);

        /**
         * @brief מעטפת נוחה לפענוח ושמירת מפתח ה-AES מתוך וקטור בתים.
         *
         * @param encryptedAesBuffer וקטור הבתים של מפתח ה-AES המוצפן.
         * @return מערך 32 הבתים של מפתח ה-AES המפוענח.
         */
        AesKeyArray decryptAndStoreAesKey(const std::vector<uint8_t>& encryptedAesBuffer);

        /**
         * @brief הצפנת תוכן קובץ (מערך בתים) באמצעות אלגוריתם `AES-CBC` עם מפתח ה-AES השמור (256 ביט / 32 בתים)
         *        ווקטור אתחול (`IV`) מאופס (16 בתים של `0x00`), כולל ריפוד PKCS#7.
         *        זורקת חריגת `std::runtime_error` אם מפתח ה-AES טרם נטען.
         *
         * @param plainData מצביע לתוכן הקובץ המקורי (לפני הצפנה).
         * @param plainSize גודל הקובץ המקורי בבתים.
         * @return וקטור בתים (`std::vector<uint8_t>`) המכיל את תוכן הקובץ המוצפן לשליחה בבקשה 828.
         */
        std::vector<uint8_t> encryptFileAesCbc(const uint8_t* plainData, size_t plainSize) const;

        /**
         * @brief מעטפת נוחה להצפנת וקטור בתים של תוכן קובץ באמצעות `AES-CBC`.
         *
         * @param plainBuffer וקטור הבתים של הקובץ המקורי.
         * @return וקטור בתים המכיל את תוכן הקובץ המוצפן.
         */
        std::vector<uint8_t> encryptFileAesCbc(const std::vector<uint8_t>& plainBuffer) const;

        /**
         * @brief בדיקה האם קיים זוג מפתחות RSA תקין במופע זה.
         */
        bool hasRsaKeys() const noexcept;

        /**
         * @brief בדיקה האם קיים מפתח AES פעיל ומוכן להצפנה במופע זה.
         */
        bool hasAesKey() const noexcept;

    private:
        mutable CryptoPP::AutoSeededRandomPool m_rng;        ///< מחולל מספרים אקראיים קריפטוגרפי
        CryptoPP::RSA::PrivateKey              m_privateKey; ///< מפתח פרטי RSA-1024
        CryptoPP::RSA::PublicKey               m_publicKey;  ///< מפתח ציבורי RSA-1024
        bool                                   m_hasRsaKeys; ///< האם מפתחות ה-RSA מאותחלים
        AesKeyArray                            m_aesKey;     ///< מפתח סימטרי AES-256 (32 בתים)
        bool                                   m_hasAesKey;  ///< האם מפתח ה-AES פוענח ומוכן לשימוש
    };

} // namespace Crypto

