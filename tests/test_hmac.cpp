#include <gtest/gtest.h>
#include "hmac.h"
#include <string>

using namespace pwman;

// Hilfs-Funktion: Hex-String → Bytes
static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(
            std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

// Hilfs-Funktion: Bytes → Hex-String (für lesbare Fehlerausgabe)
static std::string to_hex(const std::vector<uint8_t>& bytes) {
    std::string hex;
    for (uint8_t b : bytes) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        hex += buf;
    }
    return hex;
}

// Hilfs-Funktion: String → Bytes
static std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// ============================================================
// SHA-1 Tests – NIST FIPS 180-4 Test Vectors
// ============================================================
// Diese Testvektoren sind vom NIST standardisiert.
// Wenn sie passen, ist die SHA-1 Implementierung korrekt.

TEST(SHA1, EmptyString) {
    // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
    auto digest = sha1({});
    EXPECT_EQ(to_hex(digest), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

TEST(SHA1, ABC) {
    // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
    // Dies ist der erste offizielle NIST-Testvektor
    auto digest = sha1(to_bytes("abc"));
    EXPECT_EQ(to_hex(digest), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

TEST(SHA1, ABCLong) {
    // SHA1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    // = 84983e441c3bd26ebaae4aa1f95129e5e54670f1
    // Dieser Testvektor überspannt 2 SHA-1 Blöcke (> 64 Bytes)
    auto digest = sha1(to_bytes(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    EXPECT_EQ(to_hex(digest), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

TEST(SHA1, SingleCharacter) {
    // SHA1("a") = 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8
    auto digest = sha1(to_bytes("a"));
    EXPECT_EQ(to_hex(digest), "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
}

TEST(SHA1, DigestSize) {
    auto digest = sha1(to_bytes("test"));
    EXPECT_EQ(digest.size(), 20u); // SHA-1 = immer 160 Bit = 20 Bytes
}

TEST(SHA1, ExactBlockSize) {
    // Genau 64 Bytes – testet den Edge Case beim Padding
    // (Padding muss in einen neuen Block, weil kein Platz mehr ist)
    std::string input(64, 'A');
    auto digest = sha1(to_bytes(input));
    EXPECT_EQ(digest.size(), 20u);
    // SHA1("AAA...A" × 64) = 30b86e44e6001403827a62c58b08893e77cf121f
    EXPECT_EQ(to_hex(digest), "30b86e44e6001403827a62c58b08893e77cf121f");
}

TEST(SHA1, Deterministic) {
    // Gleiche Eingabe → gleicher Hash (keine Zufallskomponente)
    auto d1 = sha1(to_bytes("deterministic"));
    auto d2 = sha1(to_bytes("deterministic"));
    EXPECT_EQ(d1, d2);
}

TEST(SHA1, AvalancheEffect) {
    // Ein Bit Unterschied → komplett anderer Hash
    auto d1 = sha1(to_bytes("test1"));
    auto d2 = sha1(to_bytes("test2"));
    EXPECT_NE(d1, d2);

    // Mindestens 25% der Bits sollten sich unterscheiden
    int diff_bits = 0;
    for (size_t i = 0; i < d1.size(); ++i) {
        uint8_t xored = d1[i] ^ d2[i];
        while (xored) {
            diff_bits += xored & 1;
            xored >>= 1;
        }
    }
    EXPECT_GT(diff_bits, 40); // Von 160 Bits sollten > 40 verschieden sein
}

// ============================================================
// HMAC-SHA1 Tests – RFC 2202 Test Vectors
// ============================================================
// RFC 2202 definiert offizielle Testvektoren für HMAC-SHA1.

TEST(HMAC_SHA1, RFC2202_TestCase1) {
    // Key  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
    // Data = "Hi There"
    // HMAC = b617318655057264e28bc0b6fb378c8ef146be00
    auto key = std::vector<uint8_t>(20, 0x0B);
    auto data = to_bytes("Hi There");
    auto mac = hmac_sha1(key, data);
    EXPECT_EQ(to_hex(mac), "b617318655057264e28bc0b6fb378c8ef146be00");
}

TEST(HMAC_SHA1, RFC2202_TestCase2) {
    // Key  = "Jefe"
    // Data = "what do ya want for nothing?"
    // HMAC = effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
    auto key = to_bytes("Jefe");
    auto data = to_bytes("what do ya want for nothing?");
    auto mac = hmac_sha1(key, data);
    EXPECT_EQ(to_hex(mac), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
}

TEST(HMAC_SHA1, RFC2202_TestCase3) {
    // Key  = 0xaaaa... (20 bytes)
    // Data = 0xdddd... (50 bytes)
    // HMAC = 125d7342b9ac11cd91a39af48aa17b4f63f175d3
    auto key = std::vector<uint8_t>(20, 0xAA);
    auto data = std::vector<uint8_t>(50, 0xDD);
    auto mac = hmac_sha1(key, data);
    EXPECT_EQ(to_hex(mac), "125d7342b9ac11cd91a39af48aa17b4f63f175d3");
}

TEST(HMAC_SHA1, RFC2202_TestCase4) {
    // Key  = 0x0102030405060708090a0b0c0d0e0f10111213141516171819
    // Data = 0xcdcdcd... (50 bytes)
    // HMAC = 4c9007f4026250c6bc8414f9bf50c86c2d7235da
    auto key = from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819");
    auto data = std::vector<uint8_t>(50, 0xCD);
    auto mac = hmac_sha1(key, data);
    EXPECT_EQ(to_hex(mac), "4c9007f4026250c6bc8414f9bf50c86c2d7235da");
}

TEST(HMAC_SHA1, RFC2202_TestCase5_KeyLongerThanBlock) {
    // Key = 0xaa × 80 (länger als 64-Byte SHA-1 Blocklänge!)
    // Data = "Test Using Larger Than Block-Size Key - Hash Key First"
    // HMAC = aa4ae5e15272d00e95705637ce8a3b55ed402112
    //
    // Dieser Test prüft den Spezialfall: Key > Blocklänge → Key wird gehasht
    auto key = std::vector<uint8_t>(80, 0xAA);
    auto data = to_bytes("Test Using Larger Than Block-Size Key - Hash Key First");
    auto mac = hmac_sha1(key, data);
    EXPECT_EQ(to_hex(mac), "aa4ae5e15272d00e95705637ce8a3b55ed402112");
}

TEST(HMAC_SHA1, RFC2202_TestCase6_KeyAndDataLongerThanBlock) {
    // Key = 0xaa × 80
    // Data = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    // HMAC = e8e99d0f45237d786d6bbaa7965c7808bbff1a91
    auto key = std::vector<uint8_t>(80, 0xAA);
    auto data = to_bytes(
        "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data");
    auto mac = hmac_sha1(key, data);
    EXPECT_EQ(to_hex(mac), "e8e99d0f45237d786d6bbaa7965c7808bbff1a91");
}

TEST(HMAC_SHA1, OutputSize) {
    auto mac = hmac_sha1(to_bytes("key"), to_bytes("data"));
    EXPECT_EQ(mac.size(), 20u); // HMAC-SHA1 = immer 20 Bytes
}

TEST(HMAC_SHA1, EmptyMessage) {
    // HMAC mit leerer Nachricht muss trotzdem funktionieren
    auto mac = hmac_sha1(to_bytes("key"), {});
    EXPECT_EQ(mac.size(), 20u);
    // Sicherstellen dass es nicht alles Nullen sind
    bool all_zero = true;
    for (uint8_t b : mac) {
        if (b != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero);
}

TEST(HMAC_SHA1, DifferentKeysProduceDifferentMACs) {
    auto data = to_bytes("same message");
    auto mac1 = hmac_sha1(to_bytes("key1"), data);
    auto mac2 = hmac_sha1(to_bytes("key2"), data);
    EXPECT_NE(mac1, mac2);
}

TEST(HMAC_SHA1, DifferentMessagesProduceDifferentMACs) {
    auto key = to_bytes("same key");
    auto mac1 = hmac_sha1(key, to_bytes("message1"));
    auto mac2 = hmac_sha1(key, to_bytes("message2"));
    EXPECT_NE(mac1, mac2);
}

// ============================================================
// HMAC-SHA256 Tests – RFC 4231 Test Vectors
// ============================================================

TEST(HMAC_SHA256, RFC4231_TestCase1) {
    // Key  = 0x0b × 20
    // Data = "Hi There"
    auto key = std::vector<uint8_t>(20, 0x0B);
    auto data = to_bytes("Hi There");
    auto mac = hmac(HashAlgorithm::SHA256, key, data);
    EXPECT_EQ(to_hex(mac),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(HMAC_SHA256, RFC4231_TestCase2) {
    // Key  = "Jefe"
    // Data = "what do ya want for nothing?"
    auto key = to_bytes("Jefe");
    auto data = to_bytes("what do ya want for nothing?");
    auto mac = hmac(HashAlgorithm::SHA256, key, data);
    EXPECT_EQ(to_hex(mac),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(HMAC_SHA256, OutputSize) {
    auto mac = hmac(HashAlgorithm::SHA256, to_bytes("key"), to_bytes("data"));
    EXPECT_EQ(mac.size(), 32u); // SHA-256 = 32 Bytes
}

// ============================================================
// HMAC-SHA512 Tests – RFC 4231 Test Vectors
// ============================================================

TEST(HMAC_SHA512, RFC4231_TestCase1) {
    // Key  = 0x0b × 20
    // Data = "Hi There"
    auto key = std::vector<uint8_t>(20, 0x0B);
    auto data = to_bytes("Hi There");
    auto mac = hmac(HashAlgorithm::SHA512, key, data);
    EXPECT_EQ(to_hex(mac),
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
}

TEST(HMAC_SHA512, RFC4231_TestCase2) {
    // Key  = "Jefe"
    // Data = "what do ya want for nothing?"
    auto key = to_bytes("Jefe");
    auto data = to_bytes("what do ya want for nothing?");
    auto mac = hmac(HashAlgorithm::SHA512, key, data);
    EXPECT_EQ(to_hex(mac),
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
}

TEST(HMAC_SHA512, OutputSize) {
    auto mac = hmac(HashAlgorithm::SHA512, to_bytes("key"), to_bytes("data"));
    EXPECT_EQ(mac.size(), 64u); // SHA-512 = 64 Bytes
}

// ============================================================
// Multi-Algorithm: Gleicher Input, verschiedene Outputs
// ============================================================

TEST(HMAC_MultiAlgo, DifferentAlgorithmsProduceDifferentMACs) {
    auto key = to_bytes("shared_key");
    auto data = to_bytes("shared_data");

    auto mac1 = hmac(HashAlgorithm::SHA1, key, data);
    auto mac256 = hmac(HashAlgorithm::SHA256, key, data);
    auto mac512 = hmac(HashAlgorithm::SHA512, key, data);

    // Verschiedene Längen
    EXPECT_EQ(mac1.size(), 20u);
    EXPECT_EQ(mac256.size(), 32u);
    EXPECT_EQ(mac512.size(), 64u);

    // Verschiedene Inhalte (erste 20 Bytes vergleichen)
    EXPECT_NE(std::vector<uint8_t>(mac1.begin(), mac1.end()),
              std::vector<uint8_t>(mac256.begin(), mac256.begin() + 20));
}
