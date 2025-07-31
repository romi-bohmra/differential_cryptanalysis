#include <iostream>
 
#include <vector>
 
#include <algorithm>
 
#include <ctime>
 
#include <cstdlib> // random number generator
 
#include <iomanip> // manipulators for formatting output
 
#include <cstdint> // for fixed width integer types
 
using namespace std;
 
#define NUMBER_P 100000 // number of plaintext pairs 
 
#define DELTA_X 0x0B00 // selected input difference - given in the tutorial
 
#define DELTA_Y 0x0202 // expected difference after 4 rounds - given in the tutorial
 
#define MASK 0x0F0F // 0000111100001111
 
// S-box and inverse S-box
// define s-box - array (given in the tutorial)
uint8_t sbox[16] = {0xE, 0x4, 0xD, 0x1,
 
                    0x2, 0xF, 0xB, 0x8,
 
                    0x3, 0xA, 0x6, 0xC,
 
                    0x5, 0x9, 0x0, 0x7};
//define inverse sbox - empty array
uint8_t inv_sbox[16];
 
// Permutation table - given in the tutorial
 
uint8_t perm[16] = {0, 4, 8, 12,
 
                    1, 5, 9, 13,
 
                    2, 6, 10, 14,
 
                    3, 7, 11, 15};
 
// Apply S-box
// substitute function
uint16_t substitute(uint16_t block_s, const uint8_t sbox_table[16]) {
 
    uint16_t result = 0; // output
     // splitting into 4 samples
    for (int i = 0; i < 4; i++) {
       
        uint8_t sample = (block_s >> (12 - 4 * i)) & 0xF; //0xF = 1111 , >> bitwise right shift
        // reconstructing the substituted 16 bit result
        result |= sbox_table[sample] << (12 - 4 * i); // bitwise left shift
 
    }
 
    return result;
 
}
 
// Apply permutation
// permute function -extracts each bit from 16-bits, apply's permutation and rearranges 
uint16_t permute(uint16_t block_p) {
 
    uint16_t result = 0; //output
 
    for (int i = 0; i < 16; i++) {
        // bit extraction
        uint16_t bit = (block_p >> (15 - i)) & 1; // bitwise right shift
        // bit repositioning at the new permuted location defined by perm[i]
        result |= bit << (15 - perm[i]); // bitwise left shift
 
    }
 
    return result;
 
}
 
// Encrypt using SPN cipher
 
uint16_t encrypt(uint16_t plain_text, const uint16_t keys[5]) {
 
    uint16_t p_text = plain_text; // copy plaintext to a variable p_text
    // 4 rounds of SPN
    for (int i = 0; i < 4; i++) {
 
        p_text ^= keys[i]; // key XORing (p_text ^ keys[0])
 
        p_text = substitute(p_text, sbox); // substitution 
 
        if (i != 3) // no permutation in the last 
 
            p_text = permute(p_text); // permutation
 
    }
 
    p_text ^= keys[4]; // key xoring with the last key (p_text = p_text ^ keys[4])
 
    return p_text;
 
}
 
// Partial decrypt of last round - using guessed last round key
 
uint16_t partial_decrypt(uint16_t cipher, uint16_t key_5_guess) {

    uint16_t a = cipher ^ key_5_guess; // XORing with the key
 
    uint16_t u4 = 0;
    // splitting into 4 bits
    for (int i = 0; i < 4; i++) {
        
        uint8_t sample = (a >> (12 - 4 * i)) & 0xF; // using bitwise right shift 
 
        u4 |= inv_sbox[sample] << (12 - 4 * i); // using bitwise left shift and inverse sbox
 
    }
 
    return u4;
 
}
 
// Generate DDT for the given S-box
 
void generate_ddt(const uint8_t sbox[16]) {
 
    int ddt[16][16] = {0}; // define 16*16 ddt table
 
    for (int dx = 0; dx < 16; dx++) { // for row
 
        for (int x = 0; x < 16; x++) { // column 
 
            int x_dash = x ^ dx;

            int y1 = sbox[x];

            int y2 = sbox[x_dash];
 
            int dy = y1 ^ y2;
 
            ddt[dx][dy]++;
 
        }
 
    }
    // for printing the ddt table
    cout << "\n--- Difference Distribution Table (DDT) ---\n";
    //setw() = specifies the minimum number of characters that a value will occupy when printed
    // leaving space before the table
    cout << setw(6) << "Δx\\Δy";
    //hex - represent hexadecimal integer literals
    for (int j = 0; j < 16; j++) cout << setw(4) << hex << j;
 
    cout << endl;
 
    for (int i = 0; i < 16; i++) {
 
        cout << setw(6) << hex << i;
 
        for (int j = 0; j < 16; j++) {
            // dec - decimal format
            cout << setw(4) << dec << ddt[i][j];
 
        }
 
        cout << endl;
 
    }
 
}
 
// Differential cryptanalysis
 
void differential_attack(const uint16_t keys[5]) {
 
    vector<int> counter(256, 0); // initialize the vector with 0's of size 256 - key counter
 
    srand(time(nullptr)); // pseudo random number generator by the rand() function - to provide initial value to the rand()
 
    for (int iter = 0; iter < NUMBER_P; iter++) {
 
        uint16_t P1 = rand() & 0xFFFF; // chosen plaintext
 
        uint16_t P2 = P1 ^ DELTA_X; // DELTA_X = input difference
 
        uint16_t C1 = encrypt(P1, keys);
 
        uint16_t C2 = encrypt(P2, keys);
 
        uint16_t output_diff = C1 ^ C2;
        
        if ((output_diff & ~MASK) != 0)
 
            continue;
        //key bit 5-8 and key bit 13-16 given in tutorial - these are active in the last round
        for (int guess_5_8 = 0; guess_5_8 < 16; guess_5_8++) {
 
            for (int guess_13_16 = 0; guess_13_16 < 16; guess_13_16++) {
 
                uint16_t k5_guess = (guess_5_8 << 8) | guess_13_16; // bitwise left shift and OR
 
                uint16_t U4_1 = partial_decrypt(C1, k5_guess); // decrypt the ciphertext 1
 
                uint16_t U4_2 = partial_decrypt(C2, k5_guess); // decrypt the ciphertext 2
                // xor the above and check if it's equivalent to the output difference 
                if (((U4_1 ^ U4_2) & MASK) == (DELTA_Y & MASK)) {
 
                    int idx = (guess_5_8 << 4) | guess_13_16;
 
                    counter[idx]++; // increment the key counter
 
                }
 
            }
 
        }
 
    }
 
    cout << "\n--- Differential Cryptanalysis Result ---\n";
 
    int best_guess = 0, max_count = 0;
 
    for (int i = 0; i < 256; i++) {
 
        if (counter[i] > max_count) {
 
            best_guess = i;
 
            max_count = counter[i];
 
        }
 
    }
 
    cout << "Best subkey guess (bits 5-8, 13-16): 0x"
<< hex << setw(2) << setfill('0') << best_guess
<< dec << " (Occurrences: " << max_count << ")\n\n";
 
    vector<pair<int, int>> results; // result vector in pair -  no of occurences of the subkey, Subkey
 
    for (int i = 0; i < 256; i++) {
 
        results.emplace_back(counter[i], i);
 
    }
 
    sort(results.rbegin(), results.rend()); // sort the result vector
 
    cout << "Top 5 subkey guesses:\n";
 
    for (int i = 0; i < 5; i++) {
 
        cout << "Subkey: 0x" << hex << setw(2) << setfill('0') << results[i].second
<< ", Occurrences: " << dec << results[i].first << endl; // printing the subkey and the number of occurences 
 
    }
 
}
 
int main() {
 
    // Build inverse S-box
 
    for (int i = 0; i < 16; i++) {
 
        inv_sbox[sbox[i]] = i;
 
    }
 
    // Example key
 
   // uint16_t key[5] = {0x3A94, 0xE8C2, 0xB751, 0xF019, 0x0240};

  
 
    // Generate and print DDT
 
    generate_ddt(sbox);
 
     //Dynamically generate 5 round keys
    uint16_t key[5];
    srand(time(nullptr)); // seed random generator
 
    cout << "--- Randomly Generated Round Keys ---" << endl;
    for (int i = 0; i < 5; i++) {
        key[i] = rand() & 0xFFFF; // generate 16-bit key
        cout << "Key[" << i << "]: 0x" << hex << setw(4) << setfill('0') << key[i] << endl;
    }
    cout << endl;

    // Run differential attack
 
    differential_attack(key);
 
    return 0;
 
}
 