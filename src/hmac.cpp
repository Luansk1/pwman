#include "hmac.h"
#include <sodium.h>
#include <cstring>
#include <algorithm>

namespace pwman {

// ============================================================
// SHA-1 Implementation (RFC 3174)
// ============================================================
//
// SHA-1 verarbeitet Daten in 512-Bit-Blöcken (64 Bytes).
// Der interne State besteht aus 5 × 32-Bit-Wörtern.
// Jeder Block durchläuft 80 Runden, die den State transformieren.
//
// Schritte:
//   1. Nachricht mit Padding auf Vielfaches von 512 Bit bringen
//   2. Pro 512-Bit-Block: Message Schedule (16 → 80 Wörter expandieren)
//   3. Pro Block: 80 Runden der Kompressionsfunktion
//   4. Finalen State als 20 Bytes ausgeben

// --- Hilfsfunktionen ---

// Links-Rotation: Bits die links rausfallen kommen rechts wieder rein.
// Beispiel: rotate_left(0b10110001, 3) = 0b10001101
//
// Warum nötig? SHA-1 nutzt Rotation statt einfachem Shift,
// damit keine Bits verloren gehen → bessere Diffusion.
static inline uint32_t rotate_left(uint32_t value, unsigned int count) {
    return (value << count) | (value >> (32 - count));
}

// Big-Endian lesen: SHA-1 arbeitet intern mit Big-Endian,
// d.h. das höchstwertige Byte kommt zuerst.
// [0x12, 0x34, 0x56, 0x78] → 0x12345678
static inline uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
           (static_cast<uint32_t>(p[3]));
}

// Big-Endian schreiben: 0x12345678 → [0x12, 0x34, 0x56, 0x78]
static inline void write_be32(uint8_t* p, uint32_t value) {
    p[0] = static_cast<uint8_t>(value >> 24);
    p[1] = static_cast<uint8_t>(value >> 16);
    p[2] = static_cast<uint8_t>(value >>  8);
    p[3] = static_cast<uint8_t>(value);
}

std::vector<uint8_t> sha1(const std::vector<uint8_t>& message) {

    // --------------------------------------------------------
    // Phase 1: Padding
    // --------------------------------------------------------
    // Die Nachricht muss auf ein Vielfaches von 512 Bit (64 Bytes)
    // aufgefüllt werden. Format:
    //
    //   [Original-Nachricht] [1-Bit] [0-Bits...] [64-Bit Länge]
    //
    // Das 1-Bit markiert das Ende der Nachricht.
    // Die 64-Bit Länge ist die Bitlänge der Originalnachricht.
    //
    // Beispiel: "Hi" (2 Bytes = 16 Bit)
    //   48 69 80 00 00 ... 00 00 00 00 00 00 00 10
    //   |--| |--|                                |--- Länge: 16 Bit = 0x10
    //   "H"  "i" + 0x80 (= 1-Bit + 7 Nullbits)

    const uint64_t bit_length = static_cast<uint64_t>(message.size()) * 8;

    // Kopie der Nachricht erstellen, daran wird das Padding angehängt
    std::vector<uint8_t> padded = message;

    // 0x80 anhängen (= Binär 10000000, also 1-Bit gefolgt von 7 Nullen)
    padded.push_back(0x80);

    // Nullen auffüllen bis 8 Bytes vor dem nächsten 64-Byte-Vielfachen
    // (die letzten 8 Bytes sind für die Länge reserviert)
    while (padded.size() % 64 != 56) {
        padded.push_back(0x00);
    }

    // 64-Bit Länge in Big-Endian anhängen
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<uint8_t>(bit_length >> (i * 8)));
    }

    // Jetzt ist padded.size() garantiert ein Vielfaches von 64

    // --------------------------------------------------------
    // Phase 2: Initialer Hash-State
    // --------------------------------------------------------
    // Diese 5 Konstanten sind die Quadratwurzeln der ersten 5 Primzahlen
    // (nach einer bestimmten Formel) – vom NIST festgelegt.

    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // --------------------------------------------------------
    // Phase 3: Blöcke verarbeiten
    // --------------------------------------------------------

    const size_t num_blocks = padded.size() / 64;

    for (size_t block = 0; block < num_blocks; ++block) {
        const uint8_t* block_ptr = padded.data() + block * 64;

        // --- Message Schedule: 16 Wörter → 80 Wörter ---
        //
        // W[0..15]: Direkt aus dem 64-Byte-Block gelesen (je 4 Bytes)
        // W[16..79]: Aus vorherigen Wörtern berechnet per XOR + Rotation
        //
        // Die Expansion sorgt dafür, dass jedes Bit der Eingabe
        // Einfluss auf viele Runden hat (= Avalanche-Effekt)

        uint32_t W[80];

        // Die ersten 16 Wörter kommen direkt aus dem Block
        for (int t = 0; t < 16; ++t) {
            W[t] = read_be32(block_ptr + t * 4);
        }

        // Wörter 16-79: XOR von 4 vorherigen Wörtern, dann 1 Bit rotieren
        for (int t = 16; t < 80; ++t) {
            W[t] = rotate_left(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
        }

        // --- Kompressionsfunktion: 80 Runden ---
        //
        // 5 Arbeitsvariablen (a,b,c,d,e) starten als Kopie des State.
        // Jede Runde berechnet eine neue Version von 'a',
        // die alten Werte rücken eins weiter: a→b→c→d→e

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        for (int t = 0; t < 80; ++t) {
            uint32_t f, k;

            // Die 80 Runden sind in 4 Gruppen à 20 aufgeteilt.
            // Jede Gruppe nutzt eine andere logische Funktion und Konstante:
            //
            // Runde  0-19: Ch(b,c,d)    – "Choice": b wählt zwischen c und d
            // Runde 20-39: Parity(b,c,d) – einfaches XOR
            // Runde 40-59: Maj(b,c,d)   – "Majority": Mehrheitsentscheid
            // Runde 60-79: Parity(b,c,d) – wieder XOR

            if (t < 20) {
                // Choice: Wenn Bit in b gesetzt → nimm c, sonst → nimm d
                // Äquivalent zu: (b ? c : d) pro Bit
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (t < 40) {
                // Parity: Gerade Anzahl gesetzter Bits → 0, ungerade → 1
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (t < 60) {
                // Majority: Bit gesetzt wenn mindestens 2 von 3 gesetzt
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            // Die Kern-Berechnung pro Runde:
            // Neues a = rot5(a) + f(b,c,d) + e + k + W[t]
            // Alle Additionen sind mod 2^32 (uint32_t overflow ist gewollt!)
            uint32_t temp = rotate_left(a, 5) + f + e + k + W[t];

            // Werte durchschieben: e←d←c←rot30(b)←a←temp
            e = d;
            d = c;
            c = rotate_left(b, 30);
            b = a;
            a = temp;
        }

        // Nach allen 80 Runden: Arbeitsvariablen zum State addieren
        // (wieder mod 2^32 – das ist die "Davies-Meyer"-Konstruktion)
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // --------------------------------------------------------
    // Phase 4: Finalen Hash ausgeben
    // --------------------------------------------------------
    // Die 5 State-Wörter (je 4 Bytes) = 20 Bytes = 160 Bit
    std::vector<uint8_t> digest(20);
    write_be32(digest.data() +  0, h0);
    write_be32(digest.data() +  4, h1);
    write_be32(digest.data() +  8, h2);
    write_be32(digest.data() + 12, h3);
    write_be32(digest.data() + 16, h4);

    return digest;
}

// ============================================================
// HMAC Implementation (RFC 2104)
// ============================================================
//
// HMAC = Hash((key XOR opad) || Hash((key XOR ipad) || message))
//
// opad = 0x5C wiederholt auf Blocklänge
// ipad = 0x36 wiederholt auf Blocklänge
//
// Warum doppelt hashen?
//   Einfaches Hash(key || message) ist anfällig für Length-Extension-Attacks:
//   Ein Angreifer kann Hash(key || message || extra) berechnen, ohne key zu kennen.
//   HMAC verhindert das durch die äußere Hash-Schicht.

// Interne Daten pro Hash-Algorithmus
struct HashInfo {
    size_t block_size;   // Blocklänge des Hash-Algorithmus (Bytes)
    size_t output_size;  // Output-Länge des Hash (Bytes)
};

static HashInfo get_hash_info(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::SHA1:   return {64, 20};   // 512-Bit Blöcke, 160-Bit Output
        case HashAlgorithm::SHA256: return {64, 32};   // 512-Bit Blöcke, 256-Bit Output
        case HashAlgorithm::SHA512: return {128, 64};  // 1024-Bit Blöcke, 512-Bit Output
    }
    return {64, 20}; // fallback
}

// Wrapper: Ruft die richtige Hash-Funktion auf
// SHA-1: unsere eigene Implementierung
// SHA-256/512: libsodium (die haben das schon, kein Grund es nochmal zu bauen)
static std::vector<uint8_t> hash_data(HashAlgorithm algo,
                                      const std::vector<uint8_t>& data) {
    switch (algo) {
        case HashAlgorithm::SHA1:
            return sha1(data);

        case HashAlgorithm::SHA256: {
            std::vector<uint8_t> out(crypto_hash_sha256_BYTES);
            crypto_hash_sha256(out.data(), data.data(), data.size());
            return out;
        }

        case HashAlgorithm::SHA512: {
            std::vector<uint8_t> out(crypto_hash_sha512_BYTES);
            crypto_hash_sha512(out.data(), data.data(), data.size());
            return out;
        }
    }
    return {}; // unreachable
}

std::vector<uint8_t> hmac(HashAlgorithm algo,
                          const std::vector<uint8_t>& key,
                          const std::vector<uint8_t>& message) {

    const auto info = get_hash_info(algo);

    // --------------------------------------------------------
    // Schritt 1: Key auf Blocklänge bringen
    // --------------------------------------------------------
    //
    // - Key zu lang (> Blocklänge)? → Hashen, um ihn zu kürzen.
    //   Warum? XOR mit ipad/opad braucht exakt block_size Bytes.
    //   Hashen ist sicher weil: wenn H(k) kollidiert, wäre SHA1 gebrochen.
    //
    // - Key zu kurz (< Blocklänge)? → Mit Nullen auf Blocklänge padden.
    //   Die Nullen "verschwinden" beim XOR nicht – 0 XOR 0x36 = 0x36,
    //   das ist trotzdem ein definierter Wert.

    std::vector<uint8_t> padded_key;

    if (key.size() > info.block_size) {
        // Key hashen um ihn zu kürzen
        padded_key = hash_data(algo, key);
    } else {
        padded_key = key;
    }

    // Auf Blocklänge mit Nullen auffüllen
    padded_key.resize(info.block_size, 0x00);

    // --------------------------------------------------------
    // Schritt 2: Inner-Key und Outer-Key berechnen
    // --------------------------------------------------------
    //
    // inner_key = padded_key XOR [0x36, 0x36, ..., 0x36]
    // outer_key = padded_key XOR [0x5C, 0x5C, ..., 0x5C]
    //
    // Warum 0x36 und 0x5C?
    //   Diese Werte wurden gewählt weil sie sich in genug Bits
    //   unterscheiden (0x36 XOR 0x5C = 0x6A = 01101010),
    //   so dass inner und outer key maximal verschieden sind.

    std::vector<uint8_t> inner_key(info.block_size);
    std::vector<uint8_t> outer_key(info.block_size);

    for (size_t i = 0; i < info.block_size; ++i) {
        inner_key[i] = padded_key[i] ^ 0x36;  // ipad
        outer_key[i] = padded_key[i] ^ 0x5C;  // opad
    }

    // --------------------------------------------------------
    // Schritt 3: Inner Hash
    // --------------------------------------------------------
    //   inner_hash = Hash(inner_key || message)
    //
    //   Der inner_key "bindet" den Key an die Nachricht.
    //   Ohne den Key kann niemand den gleichen Hash produzieren.

    std::vector<uint8_t> inner_data;
    inner_data.reserve(info.block_size + message.size());
    inner_data.insert(inner_data.end(), inner_key.begin(), inner_key.end());
    inner_data.insert(inner_data.end(), message.begin(), message.end());

    std::vector<uint8_t> inner_hash = hash_data(algo, inner_data);

    // --------------------------------------------------------
    // Schritt 4: Outer Hash
    // --------------------------------------------------------
    //   result = Hash(outer_key || inner_hash)
    //
    //   Die äußere Hash-Schicht schützt gegen Length-Extension:
    //   Selbst wenn jemand inner_hash kennt, kann er ohne outer_key
    //   nicht den korrekten HMAC-Wert berechnen.

    std::vector<uint8_t> outer_data;
    outer_data.reserve(info.block_size + inner_hash.size());
    outer_data.insert(outer_data.end(), outer_key.begin(), outer_key.end());
    outer_data.insert(outer_data.end(), inner_hash.begin(), inner_hash.end());

    std::vector<uint8_t> result = hash_data(algo, outer_data);

    // Sensible Daten löschen
    sodium_memzero(padded_key.data(), padded_key.size());
    sodium_memzero(inner_key.data(), inner_key.size());
    sodium_memzero(outer_key.data(), outer_key.size());
    sodium_memzero(inner_data.data(), inner_data.size());

    return result;
}

std::vector<uint8_t> hmac_sha1(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& message) {
    return hmac(HashAlgorithm::SHA1, key, message);
}

} // namespace pwman
