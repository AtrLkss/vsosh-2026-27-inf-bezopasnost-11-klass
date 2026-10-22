#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

using namespace std;

static uint8_t mix_byte(uint8_t c, int i) {
    c ^= static_cast<uint8_t>(0x2D + i * 7);
    c = static_cast<uint8_t>((c << 3) | (c >> 5));
    c = static_cast<uint8_t>(c + 0x31 - i);
    return c;
}

static bool verify(const string& s) {
    const vector<uint8_t> target = {
        0x0B, 0x6A, 0xD1, 0xB7, 0x36, 0x85, 0x54, 0x95, 0xC1, 0x22, 0x2F, 0x6E, 0xBA, 0xE2, 0x18, 0x51, 0x37, 0x5E, 0xFB, 0x32, 0xCB, 0x09
    };

    if (s.size() != target.size()) {
        return false;
    }

    uint32_t checksum = 0;

    for (size_t i = 0; i < s.size(); ++i) {
        uint8_t x = mix_byte(
            static_cast<uint8_t>(s[i]),
            static_cast<int>(i)
        );

        if (x != target[i]) {
            return false;
        }

        checksum += static_cast<uint8_t>(s[i]) * (i + 3);
    }

    return checksum == 0x68CE;
}

int main() {
    string key;

    cout << "Enter secret text: ";
    cin >> key;

    if (verify(key)) {
        cout << "Correct!\n";
    } else {
        cout << "Wrong!\n";
    }
    return 0;
}