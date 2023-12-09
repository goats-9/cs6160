/** 
 * Name         : Gautam Singh
 * Date         : 2023-11-04
 * Roll Number  : CS21BTECH11018
 * File         : aes24bitDecryption.cpp
 * Purpose      : Use a brute-force attack to find the effective 20-bit key that
 *                is expanded and used in AES encryption given a known plaintext
 *                and ciphertext pair. Use this key to discover the secret
 *                plaintext given its corresponding ciphertext.
 */

/* Header includes */

#include "aesLongKeyGen24.c"
#include "aes-libg-example.c"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

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
 * @brief Wrapper around AES decryption function that takes a `candidate` key
 * and a `knownCipherText` and returns the corresponding plaintext for the given
 * key.
 * @param knownCipherText The ciphertext to be decrypted.
 * @param candidate The key used to generate the AES key for decryption.
 * @return An `unsigned char` array representing the decrypted plaintext for the
 * given key and ciphertext pair.
*/
std::vector<uint8_t> bruteForceDecrypt(std::vector<uint8_t> &knownCipherText, int candidate);

int main() {
    // Input handling
    std::string plaintextsFile = "aesPlaintexts.txt";
    std::string ciphertextsFile = "aesCiphertexts.txt";
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
    /**
     * Brute force attack. Each of the 2^20 possible keys is tried till a match
     * is obtained.
    */
    int i = 0;
    while (i < (1<<20)) {
        if (plaintexts[0] == bruteForceDecrypt(ciphertexts[0], i<<4)) break;
        i++;
    }
    // Error handling in case AES decryption did not work.
    if (i == (1<<20)) {
        std::cout << "[ERROR] Invalid message-ciphertext pair or AES decryption failed.\n";
        return -1;
    }
    // Here, i is the secret key that is expanded.
    // Use it to decrypt the ciphertext to find the secret plain text.
    std::vector<uint8_t> secretPlainText = bruteForceDecrypt(ciphertexts.back(), i<<4);
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

std::vector<uint8_t> bruteForceDecrypt(std::vector<uint8_t> &knownCipherText, int candidate) {
    uint8_t shortKey[3], longKey[16];
    // Generate shortKey
    genShortKey(candidate, shortKey, 3);
    // Generate longKey
    expandKey(longKey, shortKey);
    int cipherLength = knownCipherText.size();
    // Perform the AES Decryption
    std::vector<uint8_t> computedPlainText(cipherLength);
    aesDecrypt(knownCipherText.data(), cipherLength, computedPlainText.data(), longKey);
    return computedPlainText;
}