/** 
 * Name         : Gautam Singh
 * Date         : 2023-09-15
 * Roll Number  : CS21BTECH11018
 * File         : streamCipherDecryption.cpp
 * Purpose      : Find the following given multiple ciphertexts of a One-Time 
 *                Pad (OTP) reused many times.
 *                1. The key used to encrypt the message text.
 *                2. The first and last message texts.
 * Working      : We consider the message texts position by position.
 *                If a plaintext character is known, we know the key character
 *                in that position. Since spaces map [a-zA-Z] to itself under
 *                XOR, we can break positions where the plaintext character of 
 *                ANY message is a space.
 */

/* Header files */

#include <bits/stdc++.h>

using namespace std;

int main() {
    string inputFile = "streamciphertexts.txt";
    ifstream fin(inputFile);
    vector<string> inputCiphertexts;
    string hexInput;
    size_t keyLen = 0;
    // Read hexstrings
    while (fin >> hexInput) {
        inputCiphertexts.push_back(hexInput);
        // Compute key length
        keyLen = max(keyLen, hexInput.length()/2);
    }
    size_t cnt = inputCiphertexts.size();
    fin.close();
    vector<vector<unsigned char>> ciphertexts;
    vector<unsigned char> key(keyLen);
    // Decode hex strings
    for (auto &hexstr : inputCiphertexts) {
        int n = hexstr.length();
        vector<unsigned char> cipher;
        for (int i = 0; i < n; i += 2) {
            string byte = hexstr.substr(i,2);
            unsigned char ch = (unsigned char)strtoul(byte.c_str(), NULL, 16);
            cipher.push_back(ch);
        }
        ciphertexts.push_back(cipher);
    }
    // Many Time Pad attack
    // Go column by column
    for (size_t i = 0; i < keyLen; i++) {
        // Define the XOR-count of a ciphertext at a position to be 
        // the number of alphabets obtained when XORing this character 
        // with other ciphertext characters at this position.
        // It is reasonable to claim that the ciphertext with the maximum
        // XOR-count at a position had encoded a space.
        // Take one ciphertext, and xor it with others.
        int xorctr = 0, cind = -1;
        for (size_t j = 0; j < cnt; j++) { 
            // Check if the chosen ciphertext is long enough
            if (ciphertexts[j].size() <= i) continue;
            unsigned char cj = ciphertexts[j][i];
            // actr represents those XORs whose values are alphabets.
            int actr = 0;
            for (size_t k = 0; k < cnt; k++) { 
                // Skip if ciphertext is not long enough 
                // or is the same ciphertext we are XORing with.
                if (k == j || ciphertexts[k].size() <= i) continue;
                unsigned char ck = ciphertexts[k][i];
                unsigned char xjk = cj^ck;
                if (isalpha(xjk)) ++actr;
            }
            if (xorctr <= actr) {
                xorctr = actr;
                cind = j;
            }
        }
        // Recover the key character at this position.
        // Dont do this if cind = -1.
        if (cind == -1) continue;
        key[i] = ciphertexts[cind][i] ^ 32;
    }
    // Output the key
    for (unsigned char uch : key) cout << uch;
    cout << "\n";
    // Recover the first and last plaintexts
    vector<unsigned char> cfirst = ciphertexts.front(), clast = ciphertexts.back();
    for (size_t i = 0; i < cfirst.size(); i++) cout << (unsigned char)(cfirst[i]^key[i]);
    cout << "\n";
    for (size_t i = 0; i < clast.size(); i++) cout << (unsigned char)(clast[i]^key[i]);
    cout << "\n";
    return 0;
}

/**
 * First message: Encrypt, then MAC, is the correct order for secure authenticated encryption.
 * Last message: Zero-knowledge interactive proof: whatever you could compute before you interacted with me and afterward are not different. Shafi Goldwasser.
*/
