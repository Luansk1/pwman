#include "base32.h"

#include <algorithm>
#include <cctype>


namespace pwman {
    static constexpr char ENCODE_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";


    // Loopup table ASCII value -> 5-bit value (0-31), 0xFF = invalid
    static constexpr uint8_t INVALID = 0xFF;
    static constexpr uint8_t PADDING = 0xFE;

    static constexpr uint8_t make_decode_value(char c){
        if (c >= 'A' && c <= 'Z') return static_cast<uint8_t>(c - 'A');
        if (c >= '2' && c <= '7') return static_cast<uint8_t>(c - '2' + 26);
        if (c == '=') return PADDING;
        return INVALID;
    };

    // 256-entry decoding table 
    // convert value to char and return uint8_t value or INVALID/PADDING
    struct DecodeTable {
        uint8_t values[256];
        constexpr DecodeTable() : values{} {
            for (int i = 0; i < 256; ++i) {
                values[i] = make_decode_value(static_cast<char>(i));
            }
        }
    };

    static constexpr DecodeTable DECODE_TABLE{};

    std::string base32_normalize(const std::string& input){
        std::string result; 
        result.reserve(input.size());

        for (char c : input){
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '-'){
                continue; 
            }

            result += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }

        return result;
    }

    bool base32_validate(const std::string& input ){
        std::string normalized = base32_normalize(input);

        if(normalized.empty()){
            throw Base32Error("Empty input");
        }

        bool is_padding = false; 
        size_t data_len = 0; 

        for (size_t i = 0; i< normalized.size(); ++i){
            uint8_t val = DECODE_TABLE.values[static_cast<unsigned char>(normalized[i])];

            if (val == INVALID){
                return false; 
            }

            if (val == PADDING){
                is_padding = true; 
            }else if(is_padding){
                return false;
            }else{
                data_len++;
            }
        }

        if (normalized.size() % 8 != 0 && normalized.size() != data_len){
            return false;
        }

        size_t remainder = data_len % 8; 

        if(remainder == 1 || remainder == 3 ||remainder == 6){
            return false; 
        }

        return true; 
    }

    std::vector<uint8_t> base32_decode(const std::string& input){
        std::string normalized = base32_normalize(input);

        // Strip padding - reserve output size in heap.
        std::string data;
        data.reserve(normalized.size());
        for (char c : normalized){
            if(c != '='){
                data += c;
            }
        }

        for (char c : data){
            uint8_t val = DECODE_TABLE.values[static_cast<unsigned char>(c)];
            if(val == INVALID || val == PADDING){
                throw Base32Error(std::string("Invalid Base32 character: '") + c + "'");
            }
        }
        
        size_t remainder = data.size() % 8; 
        if(remainder == 1 || remainder == 3 || remainder == 6){
            throw Base32Error("Invalid Base32 length: cannot produce whole bytes");
        }  

        // Calc output size 
        // Every 8 Base32 chars = 5 bytes
        // Partial groups: 2 chars=1 bytes, 4 chars = 2 bytes, 5 chars = 3 bytes, 7 chars = 4 bytes
        size_t full_groups = data.size() / 8; 
        size_t output_size = full_groups * 5; 

        switch (remainder){
            case 2: output_size += 1; break; 
            case 4: output_size += 2; break; 
            case 5: output_size += 3; break; 
            case 7: output_size += 4; break; 
            default: break; // no partial grouping
        }

        std::vector<uint8_t> result; 
        result.reserve(output_size);


        // Decode input: accumulate 5-bit val in buffer and emit bytes when there are >= 8 bits
        uint32_t buffer = 0; 
        int bits_in_buffer = 0; 

        for (char c : data){
            uint8_t val = DECODE_TABLE.values[static_cast<unsigned char>(c)];
            buffer = (buffer << 5) | val; 
            bits_in_buffer += 5; 

            if (bits_in_buffer >= 8){
                bits_in_buffer -= 8; 
                result.push_back(static_cast<uint8_t>((buffer >> bits_in_buffer) & 0xFF));
            }
        }


        return result; 

    }

    std::string base32_encode(const std::vector<uint8_t>& data){
        if(data.empty()){
            return "";
        }

        std::string result; 
        result.reserve(((data.size() +4) / 5) * 8);

        uint32_t buffer = 0; 
        int bits_in_buffer = 0; 

        for (uint8_t byte : data){
            buffer = (buffer << 8) | byte; 
            bits_in_buffer += 8;

            while (bits_in_buffer >= 5){
                bits_in_buffer -= 5; 
                result += ENCODE_TABLE[(buffer >> bits_in_buffer) & 0x1F];
            }
        }

        if (bits_in_buffer > 0){
            result += ENCODE_TABLE[(buffer << (5 - bits_in_buffer)) & 0x1F];
        }

        while (result.size() % 8 != 0){
            result += '=';
        }

        return result; 
    }
}