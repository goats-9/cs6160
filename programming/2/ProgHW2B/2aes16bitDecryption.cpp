/** 
 * Name         : Gautam Singh
 * Date         : 2023-11-04
 * Roll Number  : CS21BTECH11018
 * File         : aes24bitDecryption.cpp
 * Purpose      : Use a brute-force attack to find the 20-bit key that is 
 *                expanded and used in AES encryption.
 */

/* Header includes */

#include "aesLongKeyGen16.c"
#include "aes-libg-example.c"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>

/* Function prototypes */

/**
 * @fn
 * @brief Read plaintext input from `file` into `buf`.
 * @param file The path of the file to be read from, relative to this file.
 * @param buf The array buffer to read the contents of `file` into.
 * @return The number of strings written to `buf`, or -1 in case of error.
*/
int readFromFile(std::string &file, std::vector<std::vector<uint8_t>> &buf);

/**
 * @fn
 * @brief Read hex strings from `file` into an array of unsigned character
 * strings `buf`.
 * @param file The path of the file to be read from, relative to this file.
 * @param buf The array buffer to read the contents of `file` into.
 * @return The number of strings written to `buf`, or -1 in case of error.
 *
*/
int readHexFromFile(std::string &file, std::vector<std::vector<uint8_t>> &buf);

/**
 * @fn
 * @brief Wrapper around AES encryption function that takes a `candidate` key
 * and a `knownPlainText` and places the corresponding ciphertext for the given
 * key and message pair in `middleCipherText`.
 * @param knownPlainText The plaintext to be decrypted.
 * @param middleCipherText The unsigned char array in which the ciphertext is to
 * be placed.
 * @param candidate The key used to generate the AES key for decryption.
 * @return void
*/
void bruteForceEncrypt(std::vector<uint8_t> &knownPlainText, std::vector<uint8_t> &middleCipherText, int candidate);

/**
 * @fn
 * @brief Wrapper around AES decryption function that takes a `candidate` key
 * and a `knownCipherText` and returns the corresponding plaintext for the given
 * key.
 * @param knownCipherText The ciphertext to be decrypted.
 * @param middleCipherText The unsigned char array in which the plaintext is to
 * be placed.
 * @param candidate The key used to generate the AES key for decryption.
 * @return void
*/
void bruteForceDecrypt(std::vector<uint8_t> &knownCipherText, std::vector<uint8_t> &middleCipherText, int candidate);

int main() {
    // Input handling
    std::string plaintextsFile = "2aesPlaintexts.txt";
    std::string ciphertextsFile = "2aesCiphertexts.txt";
    std::vector<std::vector<uint8_t>> plaintexts, ciphertexts;
    int err = readFromFile(plaintextsFile, plaintexts);
    if (err == -1) {
        std::cout << "[ERROR] Could not read from " << plaintextsFile << "\n";
        return err; 
    }
    err = readHexFromFile(ciphertextsFile, ciphertexts);
    if (err == -1) {
        std::cout << "[ERROR] Could not read from " << plaintextsFile << "\n";
        return err; 
    }
    // Lookup table to find the key given the ciphertext for a given plaintext.
    std::map<std::vector<uint8_t>, int> hashMap;
    int k1 = -1, k2 = -1;
    int i = 0;
    // Populate the lookup map
    while (i < (1<<20)) {
        std::vector<uint8_t> middleCipherText(16);
        bruteForceEncrypt(plaintexts[0], middleCipherText, i);
        hashMap[middleCipherText] = i;
        i++;
    }
    i = 0;
    // Perform a match on the lookup map
    while (i < (1<<20)) {
        std::vector<uint8_t> middleCipherText(16);
        bruteForceDecrypt(ciphertexts[0], middleCipherText, i);
        if (hashMap.find(middleCipherText) != hashMap.end()) {
            k1 = hashMap[middleCipherText];
            k2 = i;
            break;       
        }
        i++;
    }
    int sz = ciphertexts.back().size();
    std::vector<uint8_t> middleCipherText(sz), secretPlainText(sz);
    // The two keys used in succession are k1 and k2
    bruteForceDecrypt(ciphertexts.back(), middleCipherText, k2);
    bruteForceDecrypt(middleCipherText, secretPlainText, k1);
    std::cout << "Secret plaintext: ";
    for (uint8_t uch : secretPlainText) std::cout << uch;
    std::cout << "\n";
    return 0;
}

/* Function definitions */

int readFromFile(std::string &file, std::vector<std::vector<uint8_t>> &buf) {
    std::fstream fin(file, std::fstream::in);
    if (!fin) return -1;
    std::string str;
    while (fin >> str) {
        std::vector<unsigned char> bytearray(str.begin(), str.end());
        buf.push_back(bytearray);
    }
    fin.close();
    return buf.size(); 
}

int readHexFromFile(std::string &file, std::vector<std::vector<uint8_t>> &buf) {
    std::fstream fin(file, std::fstream::in);
    if (!fin) return -1;
    std::string str;
    while (fin >> str) {
        std::vector<uint8_t> bytearr; 
        int n = str.length();
        for (int i = 0; i < n; i += 2) {
            uint8_t byte;
            sscanf(str.c_str() + i, "%2hhx", &byte);
            bytearr.push_back(byte);
        }
        buf.push_back(bytearr);
    }
    fin.close();
    return buf.size();
}

/**
 * @fn
 * @brief Convert an `int` into an array of unsigned bytes.
 * @param candidate The integer to be converted.
 * @param shortKey Array to which the bytes `candidate` should be written to.
 * @param shortKeyLength The length of `shortKey`.
 * @return void
*/
void genShortKey(int candidate, uint8_t *shortKey, int shortKeyLength) {
    for (int i = shortKeyLength - 1; i >= 0; i--) {
        shortKey[i] = candidate & 0xff;
        candidate >>= 8;
    }
}

void bruteForceEncrypt(std::vector<uint8_t> &knownPlainText, std::vector<uint8_t> &middleCipherText, int candidate) {
    uint8_t shortKey[2], longKey[16];
    // Generate shortKey
    genShortKey(candidate, shortKey, 2);
    // Generate longKey
    expandKey(longKey, shortKey);
    int plainTextLength = knownPlainText.size();
    // Perform the AES Encryption
    aesEncrypt(knownPlainText.data(), plainTextLength, middleCipherText.data(), longKey);
}

void bruteForceDecrypt(std::vector<uint8_t> &knownCipherText, std::vector<uint8_t> &middleCipherText, int candidate) {
    uint8_t shortKey[2], longKey[16];
    // Generate shortKey
    genShortKey(candidate, shortKey, 2);
    // Generate longKey
    expandKey(longKey, shortKey);
    int cipherLength = knownCipherText.size();
    // Perform the AES Decryption
    aesDecrypt(knownCipherText.data(), cipherLength, middleCipherText.data(), longKey);
}