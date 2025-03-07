#include <iostream>                               // Provides functionalities for input and output (cin, cout).
#include <fstream>                                // Allows file stream handling (reading from and writing to files).
#include <vector>                                 // Implements the vector container for dynamic array handling.
#include <bitset>                                 // Enables the use of fixed-size bit sequences for binary manipulation.
#include <random>                                 // Contains functions and classes for random number generation.
#include <string>                                 // Provides the string class for handling text data.
#include <set>                                    // Implements the std::set container for storing unique elements in a sorted order.
#include <sys/stat.h>                             // Defines the struct stat and the stat() function to obtain file information (used for checking file existence and metadata).
#include <regex>                                  // Provides support for regular expressions to search, match, and manipulate strings.
#include <algorithm>                              // Offers a collection of algorithms (e.g., sorting, searching).
#include <numeric>                                // Contains numeric operations (e.g., accumulation, reduction).
#include <zlib.h>                                 // Provides functions for data compression and decompression using the zlib library.
#include <sstream>                                // Facilitates string stream operations for manipulating strings as streams.
#include <filesystem>                             // Introduces facilities for file system operations (directories, paths).
#include <iomanip>                                // Provides manipulators for input/output formatting (e.g., controlling decimal precision).
#include <openssl/sha.h>                          // Contains functions for SHA hashing using the OpenSSL library.
#include <cstring>                                // Provides functions for handling C-style strings (e.g., strcpy, strlen).
#include <limits>                                 // Defines characteristics of fundamental data types (e.g., min/max values).
#include <termios.h>                              // Provides an interface for terminal I/O attributes (for controlling terminal settings).
#include <unistd.h>                               // Contains miscellaneous symbolic constants and types, including POSIX operating system API.
#include <chrono>                                 // Provides utilities for measuring time and duration.
#include <sys/sysinfo.h>                          // Contains definitions for obtaining system information (e.g., memory usage, uptime).
#include <cctype>                                 // Provides functions for character classification and manipulation (e.g., isdigit, isalpha).
#include <omp.h>                                  // Provides support for multi-platform shared memory multiprocessing programming in C++.
#include <array>                                  // Implements the array container for fixed-size array handling.
#include <cstdio>                                 // Offers standard input/output functions like printf and scanf.
#include <csignal>                                // Provides functions to handle asynchronous events (signals).
#include <cstdlib>                                // Provides functions for memory allocation, process control, and conversions.
#include <stdexcept>                              // Contains standard exception classes for error handling.
#include <future>                                 // Provides support for asynchronous programming and future/promise functionality.
#include <immintrin.h>                            // Includes definitions for AVX and SIMD operations (if supported).
#include <zstd.h>                                 // Provides functions for data compression and decompression using the Zstandard library.
#include <boost/iostreams/device/mapped_file.hpp> // Facilitates memory-mapped file I/O using the Boost Iostreams library.
#include <sodium.h>                               // Provides functions for cryptographic operations, including password hashing and encryption, from the libsodium library.

#define VERSION "v3.0.0\n"

// ++++++++++++++++++++++++++++++++++++++++++++++++++++ Color codes class ++++++++++++++++++++++++++++++++++++++++++++++++++++ 
class bcolors {
public:
    static const std::string PURPLE;
    static const std::string BLUE;
    static const std::string BLUEL;
    static const std::string GREEN;
    static const std::string YELLOW;
    static const std::string RED;
    static const std::string UNDERLINE;
    static const std::string WHITE;
    static const std::string ORANGE;
    static const std::string VIOLET;
    static const std::string BLACK; 
};

const std::string bcolors::PURPLE = "\033[95m";
const std::string bcolors::BLUE = "\033[94m";   
const std::string bcolors::BLUEL = "\033[96m";  
const std::string bcolors::GREEN = "\033[92m";  
const std::string bcolors::YELLOW = "\033[93m"; 
const std::string bcolors::RED = "\033[91m";    
const std::string bcolors::UNDERLINE = "\033[4m"; 
const std::string bcolors::WHITE = "\033[37m";   
const std::string bcolors::ORANGE = "\033[38;5;208m"; 
const std::string bcolors::VIOLET = "\033[38;5;135m";
const std::string bcolors::BLACK = "\033[30m";   
const std::string RESET = "\033[0m";
// --------------------------------------------------------------------------------------------------------------------------------------


// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++ MEMORY CHECKING ++++++++++++++++++++++++++++++++++++++++++++++++++++++++
long long getAvailableRAM() {
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        perror("sysinfo");
        return -1; // Error getting sysinfo
    }
    return info.freeram; // Returns free RAM in bytes
}

bool checkMemoryRequirements(const std::string& filename, int padding) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    long fileSize = file.tellg(); // Get file size
    file.close();

    long requiredMemory = fileSize * (1 + padding) * 2 + (500 * 1024 * 1024); // Memory required + 500 MB
    long long availableMemory =  getAvailableRAM(); // Memmory aviable

    if (requiredMemory > availableMemory) {
        std::cerr << bcolors::RED << "Not enough RAM to process file" << RESET << std::endl;
        return false;
    }
    
    return true; // Enough RAM
}
// --------------------------------------------------------------------------------------------------------------------------------------


// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++ PROCESS SPLIT FILES ++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Split a file into parts
std::vector<std::string> splitFile(const std::string& filename, long partSize) {
    std::vector<std::string> partFiles;

    // Form and execute the split command
    std::string command = "split -b " + std::to_string(partSize) + " " + filename + " " + filename + "_part_";
    if (std::system(command.c_str()) != 0) {
        std::cerr << "Failed to execute split command: " << command << std::endl;
        return partFiles;
    }

    // Collect the names of the split files
    for (char suffix1 = 'a'; suffix1 <= 'z'; ++suffix1) {
        for (char suffix2 = 'a'; suffix2 <= 'z'; ++suffix2) {
            std::string partFilename = filename + "_part_" + suffix1 + suffix2;
            std::ifstream partFile(partFilename);
            if (!partFile) break;
            partFiles.push_back(partFilename);
        }
    }

    return partFiles;
}

// Get the path of the executable
std::string getExecutablePath() {
    char exePath[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);

    if (len != -1) {
        exePath[len] = '\0'; // Null-terminate the path
        return std::string(exePath);
    } else {
        std::cerr << "Error getting executable path" << std::endl;
        return "";
    }
}

// Encrypt or decrypt files using the executable externally
void processFiles(const std::vector<std::string>& files, const std::string& password, int padding, bool encrypt) {
    std::string exePath = getExecutablePath();
    if (exePath.empty()) {
        std::cerr << "Failed to get executable path" << std::endl;
        return;
    }

    std::string exeDir = exePath.substr(0, exePath.find_last_of("/"));
    std::string exeName = exePath.substr(exePath.find_last_of("/") + 1);
    std::string commandBase = exeDir + "/" + exeName + (encrypt ? " -e " : " -d ");

    for (const auto& file : files) {                                                                        
        std::string command = commandBase + file + " -p " + std::to_string(padding) + " -P " + password + " &> /dev/null"; 
        std::cout << bcolors::WHITE << " [" << bcolors::GREEN <<  "$" << bcolors::WHITE << "]" << (encrypt ? " Encrypting " : " Decrypting ") << "part: " << file << std::endl;
        if (std::system(command.c_str()) != 0) {
            std::cerr << "Failed to execute command: " << command << std::endl;
            break; // Stop if any part fails to process
        }
    }
}

// Archive the split files into a single archive file
void archiveFiles(const std::vector<std::string>& files, const std::string& inputFile) {
    std::ofstream archive(inputFile, std::ios::binary);
    if (!archive) {
        std::cerr << bcolors::RED << "Failed to create archive file: " << inputFile << RESET << std::endl;
        return;
    }

    // Escribir el encabezado una sola vez al inicio
    const std::string header = "_PARTS_COMBINED_";
    archive.write(header.c_str(), header.size());

    for (const auto& file : files) {
        std::ifstream partFile(file, std::ios::binary | std::ios::ate);
        if (!partFile) {
            std::cerr << bcolors::RED << "Failed to open part file: " << file << RESET << std::endl;
            continue;
        }

        std::size_t size = partFile.tellg();
        partFile.seekg(0, std::ios::beg);

        // Write part size
        archive.write(reinterpret_cast<const char*>(&size), sizeof(size));
        // Write data to encrypted part
        archive << partFile.rdbuf();
        partFile.close();
        std::remove(file.c_str()); // Del original part
    }

    archive.close();
    std::cout << bcolors::GREEN << "Combined file successfully created and parts removed!" << RESET << std::endl;
}


// Extract, merge, and prepare files for decryption
std::vector<std::string> extractFiles(const std::string& archiveFile) {
    std::ifstream archive(archiveFile, std::ios::binary);
    if (!archive) {
        std::cerr << bcolors::RED << "Can't open combined file: " << archiveFile << RESET << std::endl;
        return {};
    }

    // Verify header
    const std::string header = "_PARTS_COMBINED_";
    std::vector<char> headerBuffer(header.size());
    archive.read(headerBuffer.data(), header.size());
    if (std::string(headerBuffer.begin(), headerBuffer.end()) != header) {
        std::cerr << bcolors::RED << "Invalid Format: header don't match" << RESET << std::endl;
        archive.close();
        return {};
    }

    std::vector<std::string> extractedParts;
    int partNum = 1;

    while (archive) {
        std::size_t size;
        archive.read(reinterpret_cast<char*>(&size), sizeof(size));
        if (archive.eof()) break; // End of file

        if (!archive) {
            std::cerr << bcolors::RED << "Error reading part size" << RESET << std::endl;
            break;
        }

        std::string partName = "_part_" + std::to_string(partNum++);
        std::ofstream partFile(partName, std::ios::binary);
        if (!partFile) {
            std::cerr << bcolors::RED << "Can't create file part: " << partName << RESET << std::endl;
            continue;
        }

        std::vector<char> buffer(size);
        archive.read(buffer.data(), size);
        if (archive.gcount() != static_cast<std::streamsize>(size)) {
            std::cerr << bcolors::RED << "Error reading part data: " << partName << RESET << std::endl;
            partFile.close();
            std::remove(partName.c_str());
            continue;
        }

        partFile.write(buffer.data(), size);
        partFile.close();

        extractedParts.push_back(partName);
    }

    archive.close();
    return extractedParts;
}


// Verify if a file was split into parts
bool containsPartTag(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << bcolors::RED << "Failed to open file: " << filename << RESET << std::endl;
        return false;
    }

    const std::string header = "_PARTS_COMBINED_";
    std::vector<char> buffer(header.size());
    file.read(buffer.data(), header.size());
    file.close();

    return std::string(buffer.begin(), buffer.end()) == header;
}
// --------------------------------------------------------------------------------------------------------------------------------------

// ++++++++++++++++++++++++++++++++++++++++++++++++++++ BACKUP FILE BEFORE DECRYPT ++++++++++++++++++++++++++++++++++++++++++++++++++++
void backup(const std::string& inputFile) {
    std::string backupFile = inputFile + ".backup";
    const size_t bufferSize = 8192; // Buffer size

    std::ifstream src(inputFile, std::ios::binary);
    std::ofstream dst(backupFile, std::ios::binary);

    std::vector<char> buffer(bufferSize);
    while (src.read(buffer.data(), buffer.size())) {
        dst.write(buffer.data(), src.gcount());
    }

    dst.write(buffer.data(), src.gcount());
}
// --------------------------------------------------------------------------------------------------------------------------------------

// -=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=-
class Xorshift {
public:
    Xorshift(double seed) {
        // Decimal to uint32_t escaling & truncating
        state = static_cast<uint32_t>(seed * 10000); // Scale the decimal value
    }
    
    uint8_t operator()() {
        state ^= (state << 13);
        state ^= (state >> 17);
        state ^= (state << 5);
        return state & 1; // Returns 0 or 1
    }

private:
    uint32_t state;
};
// -=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=-

namespace fs = std::filesystem;


//=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=
class LCRYPT {
public:
    LCRYPT(const std::string& hashedPassword) : password(hashedPassword) {
        firstRound = hashPasswordRounds(password + password);
        secondRound = hashPasswordRounds(firstRound + firstRound);
        thirdRound = hashPasswordRounds(secondRound + secondRound);
        fourthRound = hashPasswordRounds(thirdRound + thirdRound);
    }

    void encrypt(const std::string& inputFile, int padding) {
        // Check if the file can be encrypted in a single pass
        if (!checkMemoryRequirements(inputFile, padding)) {
            std::ifstream file(inputFile, std::ios::binary | std::ios::ate);
            long fileSize = file.tellg();
            file.close();

            long long availableMemory =  getAvailableRAM();  // Memmory aviable
            long requiredMemory = fileSize * 2 * (1 + padding) + (500 * 1024 * 1024);
            int numberOfParts = std::ceil((double)requiredMemory / availableMemory); // Calculate the number of parts required
            numberOfParts += 1;
            if (numberOfParts < 1) numberOfParts = 1;
            if (numberOfParts == 1 && requiredMemory > availableMemory) {
                numberOfParts = 2;
            }
            long partSize = ((fileSize / numberOfParts) + 511) & ~511; ; // Calculate the size of each part

            if (partSize <= 0) partSize = 512; // Ensure partSize is positive

            std::vector<std::string> partFiles = splitFile(inputFile, partSize); // Split the file into parts
            if (partFiles.empty()) {
                std::cerr << "File splitting failed: No parts generated" << std::endl;
                return;
            }
            

            std::cout << bcolors::WHITE << " [" << bcolors::RED << "||" << bcolors::WHITE << "]"
                    << " File split into " << partFiles.size() << " parts due to insufficient RAM" << std::endl;

            processFiles(partFiles, password, padding, true); // Encrypt the parts

            archiveFiles(partFiles, inputFile); // Archive the encrypted parts into a single tar file

            std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "]"
                    << " Encrypted target saved as: " << inputFile << std::endl;

            exit(0); // Exit after encrypting the parts
        }

        // Continue with the nornal encryption process
        // Comprenssion
        std::cout << bcolors::WHITE << "\n[" << bcolors::BLUE << "%" << bcolors::WHITE << "]" << " Compressing..." << std::endl;
        compressFile(inputFile); // Compress file/folder

        auto start = std::chrono::high_resolution_clock::now(); // Start timer

        // Load File to RAM
        auto fileSize = fs::file_size(inputFile);
        std::cout << bcolors::WHITE << "\n[" << bcolors::ORANGE << "~" << bcolors::WHITE << "]" << " Loading File to RAM";
        std::size_t size;
        auto loadStart = std::chrono::high_resolution_clock::now(); 

        std::vector<uint8_t> binary = loadFileAsBits(inputFile); // Load file in RAM

        auto loadEnd = std::chrono::high_resolution_clock::now();
        auto loadDuration = std::chrono::duration_cast<std::chrono::microseconds>(loadEnd - loadStart).count(); // in microseconds
        double fileSizeGB = fileSize / (1024.0 * 1024.0 * 1024.0); // Size en GB
        double loadDurationSec = loadDuration / 1e6;                // Duración in sec
        double loadSpeedGBps = fileSizeGB / loadDurationSec;        // Velocity GB/s

        std::cout << std::fixed << std::setprecision(3);
        std::cout << "\n    ↳ Loaded file in " << loadDuration / 1000.0 << " ms at " 
                << loadSpeedGBps << " GB/s";
        

        // Shuffle each byte
        std::cout << bcolors::WHITE << "\n[" << bcolors::RED << "@" << bcolors::WHITE << "]" << " Shuffling ~bytes";
        std::hash<std::string> hashFn;
        size_t passwordHash = hashFn(firstRound);
        shuffleBytes(binary, passwordHash);
        

        // Padding *bit
        std::cout << bcolors::WHITE << "\n[" << bcolors::GREEN << "*" << bcolors::WHITE << "]" << " Adding Padding *bit";
        applyPadding(binary, padding, secondRound); // Padding for each bit
        

        // Byte to Table byte reference
        std::cout << bcolors::WHITE << "\n[" << bcolors::VIOLET << "<->" << bcolors::WHITE << "]" << " Byte to Decimal Reference";
        auto substitutionTable = generateByteSubstitutionTable(thirdRound);
        byteSubstitution(binary, substitutionTable);
        

        // XOR Key
        std::cout << bcolors::WHITE << "\n[" << bcolors::RED << "^" << bcolors::WHITE << "]" << " Applying XOR Key";
        std::array<uint8_t, SHA256_DIGEST_LENGTH> hashedPassword = hashPassword(fourthRound); 
        auto xorKey = generateXORKey(hashedPassword, binary.size());
        applyXOR(binary, xorKey);

        // Finish & save
        saveToFile(inputFile, binary);
        std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "]" << " Encrypted target saved as: " << inputFile << std::endl;
        auto end = std::chrono::high_resolution_clock::now(); // Stop timer
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        long seconds = duration / 1000;
        long milliseconds = duration % 1000;
        long minutes = seconds / 60;
        seconds %= 60;

        std::cout << bcolors::WHITE << "\n" << minutes << "m | " << seconds << "s | " << milliseconds << "ms\n\n";

    }

    void decrypt(const std::string& inputFile, int padding) {
        // Check if the file was split into parts
        if (containsPartTag(inputFile)) {
            backup(inputFile); // Create a backup

            std::cout << bcolors::YELLOW << "! The file was split due to insufficient RAM during encryption process." << std::endl;

            // Extract the parts (e.g., b_part_aa, b_part_ab, b_part_ac, ...)
            std::vector<std::string> partFiles = extractFiles(inputFile); // This should return ["b_part_aa", "b_part_ab", ...]

            // Decrypt the parts
            processFiles(partFiles, password, padding, false);

            // Now we need to brute-force search for the decrypted part files
            std::string partPrefix = inputFile + "_part_";  // Prefix of decrypted parts based on inputFile
            std::vector<std::string> decryptedParts;

            // Brute-force search for decrypted part files (e.g., <inputFile>_part_aa, <inputFile>_part_ab, ...)
            for (char suffix1 = 'a'; suffix1 <= 'z'; ++suffix1) {
                for (char suffix2 = 'a'; suffix2 <= 'z'; ++suffix2) {
                    std::string partFile = partPrefix + suffix1 + suffix2;

                    std::ifstream part(partFile, std::ios::binary);
                    if (!part) {
                        // If the part file doesn't exist, break out of the loop
                        if (suffix1 == 'a' && suffix2 == 'a') {
                            std::cerr << bcolors::RED << "No decrypted parts found for file: " << inputFile << RESET << std::endl;
                        }
                        break;  // No more parts exist, so stop searching
                    }

                    // Append found part to the decryptedParts vector
                    decryptedParts.push_back(partFile);
                    part.close(); // Close the part file
                }
            }

            // Now concatenate the decrypted parts into the final output file
            std::ofstream output(inputFile, std::ios::binary);
            if (!output) {
                std::cerr << bcolors::RED << "Failed to open output file: " << inputFile << RESET << std::endl;
                return;
            }

            // Append the decrypted parts to the output file
            for (const std::string& partFile : decryptedParts) {
                std::ifstream part(partFile, std::ios::binary);
                if (!part) {
                    std::cerr << bcolors::RED << "Failed to open decrypted part file: " << partFile << RESET << std::endl;
                    return;
                }

                output << part.rdbuf();  // Append the content of the part file to the output file
                part.close();  // Close the part file after reading it

                // Remove the part file after appending it
                std::remove(partFile.c_str());  // Delete the part file after it's been appended
            }
            
            std::cout << bcolors::GREEN << "File parts combined successfully!" << RESET << std::endl;

            output.close();  // Close the final output file

            std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "] Decrypted target saved as: " << inputFile << std::endl;

            // Remove the backup file after successful completion
            std::string backupFile = inputFile + ".backup";
            std::remove(backupFile.c_str());

            exit(0);  // Exit after completion
        }


        // Continue with the normal decryption process
        auto start = std::chrono::high_resolution_clock::now(); // Start timer
        auto fileSize = fs::file_size(inputFile);
        (inputFile); // Save backup file in case of failure

        // Load File to RAM
        std::cout << bcolors::WHITE << "\n[" << bcolors::ORANGE << "~" << bcolors::WHITE << "]" << " Loading File to RAM";
        std::size_t size;

        auto loadStart = std::chrono::high_resolution_clock::now(); 

        // Load file in RAM
        std::vector<uint8_t> binary = loadFileAsBits(inputFile);

        auto loadEnd = std::chrono::high_resolution_clock::now();
        auto loadDuration = std::chrono::duration_cast<std::chrono::microseconds>(loadEnd - loadStart).count(); // in microseconds
        double fileSizeGB = fileSize / (1024.0 * 1024.0 * 1024.0); // Size en GB
        double loadDurationSec = loadDuration / 1e6;                // Duración in sec
        double loadSpeedGBps = fileSizeGB / loadDurationSec;        // Velocity GB/s

        std::cout << std::fixed << std::setprecision(3);
        std::cout << "\n    ↳ Loaded file in " << loadDuration / 1000.0 << " ms at " 
                << loadSpeedGBps << " GB/s";
        

        // XOR Key
        std::cout << bcolors::WHITE << "\n[" << bcolors::RED << "^" << bcolors::WHITE << "]" << " Applying XOR Key";
        std::array<uint8_t, SHA256_DIGEST_LENGTH> hashedPassword = hashPassword(fourthRound); 
        auto xorKey = generateXORKey(hashedPassword, binary.size());
        applyXOR(binary, xorKey);
        

        // Byte to Table byte reference
        std::cout << bcolors::WHITE << "\n[" << bcolors::VIOLET << "<->" << bcolors::WHITE << "]" << " Byte to Decimal Reference";
        auto substitutionTable = generateByteSubstitutionTable(thirdRound);
        auto inverseTable = generateInverseSubstitutionTable(substitutionTable);
        byteSubstitutionDecrypt(binary, inverseTable);
        

        // Padding *bit
        std::cout << bcolors::WHITE << "\n[" << bcolors::GREEN << "*" << bcolors::WHITE << "]" << " Removing Padding *bit";
        removePadding(binary, padding);
        

        // Unshuffle
        std::cout << bcolors::WHITE << "\n[" << bcolors::RED << "@" << bcolors::WHITE << "]" << " Unshuffling inverted bytes";
        std::hash<std::string> hashFn;
        size_t passwordHash = hashFn(firstRound);
        reverseByteShuffle(binary, passwordHash);
        

        // Save to decompress
        saveToFile(inputFile, binary);

        // Decompresion file/folder
        std::cout << bcolors::WHITE << "\n[" << bcolors::BLUE << "%" << bcolors::WHITE << "]" << " Decompressing...";
        decompressFile(inputFile);

        // Dele backup file
        std::string backupFile = inputFile + ".backup";
        std::remove(backupFile.c_str());

        // Finish
        std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "]" << " Decrypted target saved as: " << inputFile << std::endl;
        auto end = std::chrono::high_resolution_clock::now(); // Stop timer
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        long seconds = duration / 1000;
        long milliseconds = duration % 1000;
        long minutes = seconds / 60;
        seconds %= 60;

        std::cout << bcolors::WHITE << "\n" << minutes << "m | " << seconds << "s | " << milliseconds << "ms\n\n";
    }

//=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=


private:
    std::string password;
    std::string firstRound;
    std::string secondRound;
    std::string thirdRound;
    std::string fourthRound;

    // Argonnid hashing rounds
    std::string hashPasswordRounds(const std::string& password) {
        const size_t HASH_LEN = 32;  
        const size_t OPS_LIMIT = crypto_pwhash_OPSLIMIT_INTERACTIVE; 
        const size_t MEM_LIMIT = crypto_pwhash_MEMLIMIT_INTERACTIVE; 
        const int ALG = crypto_pwhash_ALG_ARGON2ID13; 

        unsigned char hash[HASH_LEN]; 

        unsigned char salt[crypto_pwhash_SALTBYTES];
        crypto_generichash(salt, sizeof(salt), reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), nullptr, 0);

        if (crypto_pwhash(hash, HASH_LEN, password.c_str(), password.size(), salt,
                          OPS_LIMIT, MEM_LIMIT, ALG) != 0) {
            throw std::runtime_error("Error: Not enough memory for hashing.");
        }

        std::ostringstream oss;
        for (size_t i = 0; i < HASH_LEN; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        return oss.str(); 
    }

// ++++++++++++++++++++++++++++++++++++++++++++++++++++ Print Bit Chain (debugging) ++++++++++++++++++++++++++++++++++++++++++++++++++++
    void printBits(const std::vector<uint8_t>& binary) {
        std::cout << std::endl;
        for (const uint8_t& byte : binary) {
            // print bits from unit8_t
            for (int j = 7; j >= 0; --j) { // Print de MSB to LSB
                std::cout << ((byte >> j) & 1);
            }
        }
        std::cout << std::endl; 
    }
// --------------------------------------------------------------------------------------------------------------------------------------


// ++++++++++++++++++++++++++++++++++++++++++++++++++++ Compressing / Decompressing ++++++++++++++++++++++++++++++++++++++++++++++++++++
    struct TarHeader {
        char name[100];
        char mode[8];
        char uid[8];
        char gid[8];
        char size[12];
        char mtime[12];
        char checksum[8];
        char typeflag[1];
        char linkname[100];
        char magic[6];
        char version[2];
        char uname[32];
        char gname[32];
        char devmajor[8];
        char devminor[8];
        char prefix[155];
        char pad[12];
    };

    void create_tar_archive(const fs::path& input_path, const fs::path& tar_file) {
        std::ofstream tar(tar_file, std::ios::binary);
        if (!tar) {
            throw std::runtime_error("Failed to create tar file: " + tar_file.string());
        }
    
        std::set<std::string> directories; // Para rastrear directorios ya archivados
    
        // Archivar si es un directorio
        if (fs::is_directory(input_path)) {
            std::string root_dir = input_path.filename().string() + "/";
    
            // Archivar la carpeta raíz primero
            TarHeader root_header = {};
            if (root_dir.size() > sizeof(root_header.name) - 1) {
                throw std::runtime_error("Root directory path too long for tar: " + root_dir);
            }
    
            strncpy(root_header.name, root_dir.c_str(), sizeof(root_header.name) - 1);
            sprintf(root_header.mode, "%07o", 0755);
            sprintf(root_header.size, "%011lo", 0);
            sprintf(root_header.mtime, "%011lo", (unsigned long)fs::last_write_time(input_path).time_since_epoch().count() / 1000000000);
            strcpy(root_header.magic, "ustar");
            strcpy(root_header.version, "00");
            root_header.typeflag[0] = '5'; // Directorio
    
            unsigned int sum = 0;
            unsigned char* p = reinterpret_cast<unsigned char*>(&root_header);
            for (int i = 0; i < 512; ++i) {
                sum += (i >= 148 && i < 156) ? ' ' : p[i];
            }
            sprintf(root_header.checksum, "%06o ", sum);
    
            tar.write(reinterpret_cast<const char*>(&root_header), 512);
    
            // Archivar todos los directorios y archivos dentro de la carpeta
            for (const auto& entry : fs::recursive_directory_iterator(input_path)) {
                std::string relative_path = fs::relative(entry.path(), input_path).string();
                std::string full_path = root_dir + relative_path;
    
                if (entry.is_directory()) {
                    std::string dir_path = full_path + "/";
                    if (directories.insert(dir_path).second) {
                        TarHeader header = {};
                        if (dir_path.size() > sizeof(header.name) - 1) {
                            throw std::runtime_error("Directory path too long for tar: " + dir_path);
                        }
                        strncpy(header.name, dir_path.c_str(), sizeof(header.name) - 1);
                        sprintf(header.mode, "%07o", 0755);
                        sprintf(header.size, "%011lo", 0);
                        sprintf(header.mtime, "%011lo", (unsigned long)fs::last_write_time(entry.path()).time_since_epoch().count() / 1000000000);
                        strcpy(header.magic, "ustar");
                        strcpy(header.version, "00");
                        header.typeflag[0] = '5'; // Directorio
    
                        sum = 0;
                        p = reinterpret_cast<unsigned char*>(&header);
                        for (int i = 0; i < 512; ++i) {
                            sum += (i >= 148 && i < 156) ? ' ' : p[i];
                        }
                        sprintf(header.checksum, "%06o ", sum);
    
                        tar.write(reinterpret_cast<const char*>(&header), 512);
                    }
                } else if (entry.is_regular_file()) {
                    TarHeader header = {};
                    if (full_path.size() > sizeof(header.name) - 1) {
                        throw std::runtime_error("File path too long for tar: " + full_path);
                    }
                    strncpy(header.name, full_path.c_str(), sizeof(header.name) - 1);
                    sprintf(header.mode, "%07o", 0644);
                    sprintf(header.size, "%011lo", (unsigned long)fs::file_size(entry.path()));
                    sprintf(header.mtime, "%011lo", (unsigned long)fs::last_write_time(entry.path()).time_since_epoch().count() / 1000000000);
                    strcpy(header.magic, "ustar");
                    strcpy(header.version, "00");
                    header.typeflag[0] = '0'; // Archivo regular
    
                    sum = 0;
                    p = reinterpret_cast<unsigned char*>(&header);
                    for (int i = 0; i < 512; ++i) {
                        sum += (i >= 148 && i < 156) ? ' ' : p[i];
                    }
                    sprintf(header.checksum, "%06o ", sum);
    
                    tar.write(reinterpret_cast<const char*>(&header), 512);
    
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (!file) {
                        throw std::runtime_error("Failed to open file: " + entry.path().string());
                    }
                    tar << file.rdbuf();
    
                    size_t bytes_written = fs::file_size(entry.path());
                    size_t padding = (512 - (bytes_written % 512)) % 512;
                    char zero[512] = {0};
                    tar.write(zero, padding);
                }
            }
        } else {
            // Archive individual file
            TarHeader header = {};
            std::string filename = input_path.filename().string();
            std::cout << "Archiving: " << filename << "\n";
            strncpy(header.name, filename.c_str(), sizeof(header.name) - 1);
            sprintf(header.mode, "%07o", 0644);
            sprintf(header.size, "%011lo", (unsigned long)fs::file_size(input_path));
            sprintf(header.mtime, "%011lo", (unsigned long)fs::last_write_time(input_path).time_since_epoch().count() / 1000000000);
            strcpy(header.magic, "ustar");
            strcpy(header.version, "00");
            header.typeflag[0] = '0'; // Archivo regular
    
            unsigned int sum = 0;
            unsigned char* p = reinterpret_cast<unsigned char*>(&header);
            for (int i = 0; i < 512; ++i) {
                sum += (i >= 148 && i < 156) ? ' ' : p[i];
            }
            sprintf(header.checksum, "%06o ", sum);
    
            tar.write(reinterpret_cast<const char*>(&header), 512);
    
            std::ifstream file(input_path, std::ios::binary);
            if (!file) {
                throw std::runtime_error("Failed to open file: " + input_path.string());
            }
            tar << file.rdbuf();
    
            size_t bytes_written = fs::file_size(input_path);
            size_t padding = (512 - (bytes_written % 512)) % 512;
            char zero[512] = {0};
            tar.write(zero, padding);
        }
    
        // Finalizar el TAR con bloques vacíos
        char zero[512] = {0};
        tar.write(zero, 512);
        tar.write(zero, 512);
    }
    

    void extract_tar_archive(const fs::path& tar_file, const fs::path& output_dir) {
        std::ifstream tar(tar_file, std::ios::binary);
        if (!tar) {
            throw std::runtime_error("Failed to open tar file: " + tar_file.string());
        }
    
        fs::create_directories(output_dir);
    
        while (tar) {
            TarHeader header;
            tar.read(reinterpret_cast<char*>(&header), 512);
            if (!tar || std::string(header.name).empty()) break;
    
            unsigned long size = std::strtoul(header.size, nullptr, 8);
            std::string file_path = (output_dir / header.name).string();
    
            if (header.typeflag[0] == '5') { // Directorio
                fs::create_directories(file_path);
                // No hay datos para leer, solo avanzamos
            } else if (header.typeflag[0] == '0' || header.typeflag[0] == '\0') { // Archivo regular
                fs::create_directories(fs::path(file_path).parent_path());
    
                std::ofstream file(file_path, std::ios::binary);
                if (!file) {
                    throw std::runtime_error("Failed to create file: " + file_path);
                }
    
                std::vector<char> buffer(size);
                tar.read(buffer.data(), size);
                file.write(buffer.data(), size);
    
                size_t padding = (512 - (size % 512)) % 512;
                tar.seekg(padding, std::ios::cur);
            } else {
                tar.seekg((size + 511) / 512 * 512, std::ios::cur); // Saltar otros tipos
            }
        }
    }

    // Función para leer un archivo completo en un vector de bytes
    std::vector<char> readFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        return std::vector<char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    }

    // Función para escribir un vector de bytes en un archivo
    void writeFile(const std::string& filePath, const std::vector<char>& data) {
        std::ofstream file(filePath, std::ios::binary);
        file.write(data.data(), data.size());
    }

    // Función para formatear el tamaño del archivo
    std::string formatFileSize(size_t size) {
        std::ostringstream oss;
        if (size >= (1 << 30)) {
            oss << (size >> 30) << " GiB";
        } else if (size >= (1 << 20)) {
            oss << (size >> 20) << " MiB";
        } else if (size >= (1 << 10)) {
            oss << (size >> 10) << " KiB";
        } else {
            oss << size << " bytes";
        }
        return oss.str();
    }

    // Función para comprimir un archivo o directorio
    void compressFile(const std::string& inputFile) {
        if (!fs::exists(inputFile) || (fs::is_directory(inputFile) && fs::is_empty(inputFile))) return;
    
        fs::path inputPath(inputFile);
        fs::path absolutePath = fs::absolute(inputPath);
        std::string directory = absolutePath.parent_path().string();
        std::string fileName = absolutePath.filename().string();
    
        if (!fs::exists(directory)) {
            std::cerr << "Directory does not exist: " << directory << std::endl;
            return;
        }
    
        auto currentPath = fs::current_path();
        fs::current_path(directory);
    
        std::string tarFile = fileName + ".tar";
        std::string zstdFile = fileName + ".zst";
    
        create_tar_archive(absolutePath, tarFile);
    
        auto originalSize = fs::file_size(tarFile);
    
        std::vector<char> fileData = readFile(tarFile);
        size_t compressedSize = ZSTD_compressBound(fileData.size());
        std::vector<char> compressedData(compressedSize);
    
        compressedSize = ZSTD_compress(compressedData.data(), compressedSize, fileData.data(), fileData.size(), 3);
        if (ZSTD_isError(compressedSize)) {
            std::cerr << "Compression error: " << ZSTD_getErrorName(compressedSize) << std::endl;
            fs::current_path(currentPath);
            return;
        }
    
        compressedData.resize(compressedSize);
        writeFile(zstdFile, compressedData);
        fs::remove(tarFile);
        fs::remove_all(fileName);
        fs::rename(zstdFile, fileName);
    
        fs::current_path(currentPath);
    
        auto compressedFileSize = compressedData.size();
        int reductionPercentage = static_cast<int>(100.0 * (originalSize - compressedFileSize) / originalSize);
        std::cout << "    ↳ Reduced ~" 
                  << std::fixed << std::setprecision(2) << reductionPercentage 
                  << "% => " << std::fixed << std::setprecision(0) 
                  << formatFileSize(compressedFileSize) << " total bits" << std::endl;
    }

    // Función para descomprimir un archivo
    void decompressFile(const std::string& inputFile) {
        auto currentPath = fs::current_path();
        try {
            std::string zstdFile = inputFile + ".zst";
            std::string tarFile = inputFile + ".tar";
    
            // Renombrar el archivo encriptado a .zst para procesarlo
            fs::rename(inputFile, zstdFile);
            std::vector<char> compressedData = readFile(zstdFile);
    
            unsigned long long decompressedSize = ZSTD_getFrameContentSize(compressedData.data(), compressedData.size());
            if (decompressedSize == ZSTD_CONTENTSIZE_UNKNOWN) {
                throw std::runtime_error("Incorrect password or padding");
            }
    
            std::vector<char> decompressedData(decompressedSize);
            decompressedSize = ZSTD_decompress(decompressedData.data(), decompressedSize, compressedData.data(), compressedData.size());
            if (ZSTD_isError(decompressedSize)) {
                throw std::runtime_error("Incorrect password or padding");
            }
    
            // Escribir el .tar temporal
            writeFile(tarFile, decompressedData);
            fs::remove(zstdFile);
    
            // Determinar el directorio de salida
            fs::path inputPath(inputFile);
            fs::path outputDir = inputPath.parent_path(); // Directorio padre
            if (outputDir.empty()) {
                outputDir = "."; // Usar el directorio actual si no hay padre
            }
    
            // Extraer el .tar en el directorio padre
            extract_tar_archive(tarFile, outputDir);
            fs::remove(tarFile);
    
            fs::current_path(currentPath);

        } catch (const std::exception& e) {
            std::cerr << "\n\n[" << bcolors::RED << "!" << bcolors::WHITE << "]" << " Error decompressing:" << bcolors::RED << " " << e.what() << bcolors::WHITE << "\n    ↳ Backup file saved as: " << bcolors::GREEN << inputFile << ".backup" << std::endl;
            std::string zstdFile = inputFile + ".zst";
            if (fs::exists(zstdFile)) fs::rename(zstdFile, inputFile);
            fs::current_path(currentPath);
            exit(1);
        }
    }
// --------------------------------------------------------------------------------------------------------------------------------------


// ++++++++++++++++++++++++++++++++++++++++++++++++++++ Load File Bits To RAM +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
std::vector<uint8_t> loadFileAsBits(const std::string& filePath) {
    boost::iostreams::mapped_file mmap(filePath, boost::iostreams::mapped_file::readonly);

    // Vector with data
    return std::vector<uint8_t>(mmap.const_data(), mmap.const_data() + mmap.size());
}
// --------------------------------------------------------------------------------------------------------------------------------------


// ++++++++++++++++++++++++++++++++++++++++++++++++++++ APPLY / REMOVE PADDING ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    // Function to add padding from binary data
    void applyPadding(std::vector<uint8_t>& binaryData, int padding, const std::string& passwordHash) {
        if (padding <= 0) return; // Return if padding is not positive

        double seedValue = static_cast<double>(std::hash<std::string>{}(passwordHash)) / 1000000000.0; // lower range
        Xorshift generator(seedValue); // generator with decimal value

        size_t totalBits = binaryData.size() * 8; // Calculate total bits in binary data
        size_t newSize = totalBits * (1 + padding); // Calculate new size with padding
        std::vector<uint8_t> paddedData((newSize + 7) / 8, 0); // Create a vector to hold padded data
        size_t index = 0; // Index for accessing bits in paddedData

        for (const auto& byte : binaryData) { // Iterate through each byte in binaryData
            for (int i = 7; i >= 0; --i) { // Process each bit from most significant to least significant
                // Generate and write padding bits
                for (int j = 0; j < padding; ++j) {
                    paddedData[index / 8] |= (generator() & 1) << (7 - (index % 8)); // Insert padding bit
                    index++;
                }
                // Write the original bit
                paddedData[index / 8] |= ((byte >> i) & 1) << (7 - (index % 8)); // Insert original bit
                index++;
            }
        }
        binaryData.swap(paddedData); // Replace original data with padded data
    }

    // Function to remove padding from binary data
    void removePadding(std::vector<uint8_t>& binaryData, int padding) {
        // If padding is negative or zero, return immediately as padding cannot be negative or zero
        if (padding <= 0) return;

        size_t totalBits = binaryData.size() * 8;
        size_t originalSize = totalBits / (padding + 1);
        std::vector<uint8_t> originalData((originalSize + 7) / 8, 0);

        size_t index = 0, originalIndex = 0;

        while (index < totalBits) {
            // Skip over the padding bits by incrementing the index by the padding size
            index += padding;

            if (index >= totalBits) break;

            // Read the corresponding bit from the binaryData
            const auto& byte = binaryData[index / 8];
            
            // Extract the bit from the byte at the specified position and store it in originalData
            originalData[originalIndex / 8] |= ((byte >> (7 - (index % 8))) & 1) << (7 - (originalIndex % 8));
            
            originalIndex++;
            index++;
        }

        // Swap the original data back into binaryData, replacing the padded data
        binaryData.swap(originalData);
    }


// --------------------------------------------------------------------------------------------------------------------------------------


// ++++++++++++++++++++++++++++++++++++++++++++++++++++ INDIVIDUAL ~Byte SHUFFLE ++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    static uint8_t shuffleByte(uint8_t originalByte, size_t passwordHash, size_t index) { // Thread Task
        static const std::array<uint8_t, 8> bitPatterns = {0, 1, 2, 3, 4, 5, 6, 7};
        std::array<uint8_t, 8> shuffledPatterns = bitPatterns;
        std::default_random_engine generator(passwordHash + index);
        std::shuffle(shuffledPatterns.begin(), shuffledPatterns.end(), generator);

        uint8_t shuffledByte = 0;
        for (size_t j = 0; j < 8; ++j) {
            shuffledByte |= ((originalByte >> (7 - j)) & 1) << shuffledPatterns[j];
        }

        return shuffledByte;
    }

    static uint8_t reverseShuffleByte(uint8_t mixedByte, size_t passwordHash, size_t index) { // Thread Task
        static const std::array<uint8_t, 8> bitPatterns = {0, 1, 2, 3, 4, 5, 6, 7};
        std::array<uint8_t, 8> shuffledPatterns = bitPatterns;
        std::default_random_engine generator(passwordHash + index);
        std::shuffle(shuffledPatterns.begin(), shuffledPatterns.end(), generator);

        std::array<uint8_t, 8> reversePatterns;
        for (size_t j = 0; j < 8; ++j) {
            reversePatterns[shuffledPatterns[j]] = j;
        }

        uint8_t restoredByte = 0;
        for (size_t j = 0; j < 8; ++j) {
            restoredByte |= ((mixedByte >> j) & 1) << (7 - reversePatterns[j]);
        }

        return restoredByte;
    }

    // Process bytes with shuffle/unshuffle
    void processBytes(std::vector<uint8_t>& binaryData, size_t passwordHash, bool shuffle) {
        unsigned int numCores = std::thread::hardware_concurrency();
        size_t size = binaryData.size();
        size_t segmentSize = (size + numCores - 1) / numCores;
        std::vector<std::future<void>> futures;

        for (unsigned int i = 0; i < numCores; ++i) {
            size_t start = i * segmentSize;
            size_t end = std::min(start + segmentSize, size);

            if (start < size) {
                futures.emplace_back(std::async(std::launch::async, [&, start, end, passwordHash, shuffle]() {
                    for (size_t j = start; j < end; ++j) {
                        if (shuffle) {
                            binaryData[j] = shuffleByte(binaryData[j], passwordHash, j);
                        } else {
                            binaryData[j] = reverseShuffleByte(binaryData[j], passwordHash, j);
                        }
                    }
                }));
            }
        }

        for (auto& future : futures) {
            future.get(); // Wait to finalize
        }
    }

    // Shuffle bytes
    void shuffleBytes(std::vector<uint8_t>& binaryData, size_t passwordHash) {
        processBytes(binaryData, passwordHash, true);
    }

    // Unshuffle bytes
    void reverseByteShuffle(std::vector<uint8_t>& binaryData, size_t passwordHash) {
        processBytes(binaryData, passwordHash, false);
    }

// --------------------------------------------------------------------------------------------------------------------------------------


// +++++++++++++++++++++++++++++++++++++++++++++++++++++++ BYTE TABLE SUBSTITUTION ++++++++++++++++++++++++++++++++++++++++++++++++++++++

    std::array<uint8_t, 256> generateByteSubstitutionTable(const std::string& password) {     // Generate Table
        std::array<uint8_t, 256> table;
        std::iota(table.begin(), table.end(), 0); // Initialize table with 0-255 values

        std::default_random_engine generator(std::hash<std::string>{}(password)); // Generate seed with passwd
        std::shuffle(table.begin(), table.end(), generator); // Shuffle table

        return table; 
    }

    std::array<uint8_t, 256> generateInverseSubstitutionTable(const std::array<uint8_t, 256>& table) {     // Generate inverse Table
        std::array<uint8_t, 256> inverseTable = {}; // Initialize inverse Table

        for (size_t i = 0; i < 256; ++i) {
            inverseTable[table[i]] = static_cast<uint8_t>(i); // Fills Table
        }

        return inverseTable; 
    }

    // Thread task
    static void byteSubstitutionSegment(std::vector<uint8_t>& binaryData, const std::array<uint8_t, 256>& substitutionTable, size_t start, size_t end) {
        for (size_t i = start; i < end; ++i) {
            binaryData[i] = substitutionTable[binaryData[i]]; // Storage substituted byte
        }
    }

    // This Step ==> [Original Byte -> Table byte substitution] || [Table byte substitution -> Original Byte] 
    void byteSubstitution(std::vector<uint8_t>& binaryData, const std::array<uint8_t, 256>& substitutionTable) {
        size_t size = binaryData.size();
        unsigned int numCores = std::thread::hardware_concurrency();
        size_t segmentSize = (size + numCores - 1) / numCores; // Round
        std::vector<std::future<void>> futures;

        for (unsigned int i = 0; i < numCores; ++i) {
            size_t start = i * segmentSize;
            size_t end = std::min(start + segmentSize, size);
            if (start < size) {
                futures.emplace_back(std::async(std::launch::async, byteSubstitutionSegment, std::ref(binaryData), std::cref(substitutionTable), start, end)); // Execute with multithread
            }
        }

        for (auto& future : futures) {
            future.get(); // Wait to fnialize
        }
    }

    // Thread task
    static void byteSubstitutionDecryptSegment(std::vector<uint8_t>& binaryData, const std::array<uint8_t, 256>& inverseTable, size_t start, size_t end) {
        for (size_t i = start; i < end; ++i) {
            binaryData[i] = inverseTable[binaryData[i]]; // Storages original byte
        }
    }

    // [Original Byte -> Table byte substitution] || [Table byte substitution -> Original Byte]  <== This step
    void byteSubstitutionDecrypt(std::vector<uint8_t>& binaryData, const std::array<uint8_t, 256>& inverseTable) {
        size_t size = binaryData.size();
        unsigned int numCores = std::thread::hardware_concurrency();
        size_t segmentSize = (size + numCores - 1) / numCores; // Round
        std::vector<std::future<void>> futures;

        for (unsigned int i = 0; i < numCores; ++i) {
            size_t start = i * segmentSize;
            size_t end = std::min(start + segmentSize, size);
            if (start < size) {
                futures.emplace_back(std::async(std::launch::async, byteSubstitutionDecryptSegment, std::ref(binaryData), std::cref(inverseTable), start, end)); // Execute with multithread
            }
        }

        for (auto& future : futures) {
            future.get(); // Wait to finalize
        }
    }

// -----------------------------------------------------------------------------------------------------------------------------------------------------------------


// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ XOR Key +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 

    static std::array<uint8_t, SHA256_DIGEST_LENGTH> hashPassword(const std::string& password) {     // Hash password to uint8_t array
        std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
        SHA256(reinterpret_cast<const uint8_t*>(password.c_str()), password.size(), hash.data());
        return hash; // Returns hash as an array
    }

    // Generate XOR Key string with password hash
    std::vector<uint8_t> generateXORKey(const std::array<uint8_t, SHA256_DIGEST_LENGTH>& passwordHash, size_t dataSize) {
        std::vector<uint8_t> key(dataSize);
        for (size_t i = 0; i < dataSize; ++i) {
            key[i] = passwordHash[i % SHA256_DIGEST_LENGTH]; // Only use Hash
        }
        return key;
    }

    // Apply XOR Key in thread segments
    static void xorSegment(std::vector<uint8_t>& binaryData, const uint8_t* key, size_t keyLength, size_t start, size_t end) {
        for (size_t i = start; i < end; ++i) {
            binaryData[i] ^= key[i % keyLength]; // Apply XOR with Key
        }
    }

    void applyXOR(std::vector<uint8_t>& binaryData, const std::vector<uint8_t>& key) {
        size_t size = binaryData.size();
        unsigned int numCores = std::thread::hardware_concurrency();
        size_t segmentSize = (size + numCores - 1) / numCores;
        std::vector<std::future<void>> futures;

        const uint8_t* keyPtr = key.data(); // Pointer to key

        for (unsigned int i = 0; i < numCores; ++i) { // Apply with multithread
            size_t start = i * segmentSize;
            size_t end = std::min(start + segmentSize, size);
            if (start < size) {
                futures.emplace_back(std::async(std::launch::async, xorSegment, std::ref(binaryData), keyPtr, key.size(), start, end));
            }
        }

        for (auto& future : futures) {
            future.get(); // Wait to finalize
        }
    }

// -----------------------------------------------------------------------------------------------------------------------------------------------------------------


// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ SAVE CHANGES +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

void saveToFile(const std::string& filename, const std::vector<uint8_t>& binaryData) {
    std::ofstream output(filename, std::ios::binary);
    if (!output.is_open()) {
        throw std::runtime_error("Error opening file to write: " + filename);
    }

    // Directly write data to file
    output.write(reinterpret_cast<const char*>(binaryData.data()), binaryData.size());

    // Chechk if succesfull
    if (!output) {
        throw std::runtime_error("Error writing to file: " + filename);
    }

    output.close();  
}

// -----------------------------------------------------------------------------------------------------------------------------------------------------------------
};


// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++Dissable eco on terminal+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void SetStdinEcho(bool enable) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty); // Obtain terminal attributes
    if (!enable) {
        tty.c_lflag &= ~ECHO;      // Dissables eco
    } else {
        tty.c_lflag |= ECHO;       // Enables eco
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty); // Apply changes
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Display Hash Maze +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void displayHashMaze(const std::string &hash) {
    for (char c : hash) {
        int value = (c >= 'a') ? c - 'a' + 10 : c - '0'; // Hex to number
        if (value < 8) {
            std::cout << " "; // Space for lower numbers
        } else {
            std::cout << "#"; // # for higher numbers
        }
    }
    std::cout << std::endl;
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Manage CTL + C Exit +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void signalHandler(int signum) {
    std::cout << bcolors::WHITE << "\n\n[" << bcolors::RED << "!" << bcolors::WHITE << "] ""Exiting...\n";
    exit(0); // Exit program
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Hash Password +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
std::string hashPassword(const std::string& password) {
    const size_t HASH_LEN = 32;  // Desired length of the final hash
    const size_t OPS_LIMIT = crypto_pwhash_OPSLIMIT_INTERACTIVE; // Interactive limit for Argon2id operations
    const size_t MEM_LIMIT = crypto_pwhash_MEMLIMIT_INTERACTIVE; // Interactive memory limit for Argon2id
    const int ALG = crypto_pwhash_ALG_ARGON2ID13; // Algorithm version: Argon2id

    unsigned char hash[HASH_LEN]; // Buffer to hold the final Argon2id hash

    // Derive a deterministic salt from the password
    unsigned char salt[crypto_pwhash_SALTBYTES];
    crypto_generichash(salt, sizeof(salt), reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), nullptr, 0);

    // Generate the Argon2id hash using the derived salt
    if (crypto_pwhash(hash, HASH_LEN, password.c_str(), password.size(), salt,
                      OPS_LIMIT, MEM_LIMIT, ALG) != 0) {
        throw std::runtime_error("Error: Not enough memory for hashing.");
    }

    // Convert the final hash to a hexadecimal string
    std::ostringstream oss;
    for (size_t i = 0; i < HASH_LEN; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return oss.str(); // Return the hex string representation of the hash
}



// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Display  Help Message +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void showHelp() {
    std::cout << "Usage: ./C-LCRYPT [options]\n"
              << "Options:\n"
              << "  -e <target>       Encrypt the specified file/folder\n"
              << "  -d <target>       Decrypt the specified file/folder\n"
              << "  -p <padding>      Specify the padding (0-∞)\n"
              << "  -P <password>     Specify the password\n"
              << "  --version         Show the current installed version\n"
              << "  -h                Display this help message\n"
              << "Examples:\n"
              << "  ./C-LCRYPT -e target -p 10 -P my_password\n"
              << "  ./C-LCRYPT -d target -p 10 -P my_password\n\n" 
              << bcolors::GREEN << "If executed without arguments, interactive mode will start." << std::endl;
} 

bool isFile(const std::string& path) { // Chech if -P (passwd) is a file
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);  // Verifica si el archivo existe
}

int main(int argc, char *argv[]) {
    
    std::signal(SIGINT, signalHandler); // Intercept CTL + C
    
    if (argc == 1) { // Execute interactive program if not arguments
        int option;
        std::string password;
        
        std::cout << bcolors::RED << "      ::::::::               :::        ::::::::  :::::::::  :::   ::: ::::::::: :::::::::::" << RESET << std::endl;
        std::cout << bcolors::RED << "    :+:    :+:              :+:       :+:    :+: :+:    :+: :+:   :+: :+:    :+:    :+:     " << RESET << std::endl;
        std::cout << bcolors::RED << "   +:+                     +:+       +:+        +:+    +:+  +:+ +:+  +:+    +:+    +:+      " << RESET << std::endl;
        std::cout << bcolors::RED << "  +#+       +#++:++#++:++ +#+       +#+        +#++:++#:    +#++:   +#++:++#+     +#+       " << RESET << std::endl;
        std::cout << bcolors::RED << " +#+                     +#+       +#+        +#+    +#+    +#+    +#+           +#+        " << RESET << std::endl;
        std::cout << bcolors::RED << "#+#    #+#              #+#       #+#    #+# #+#    #+#    #+#    #+#           #+#         " << RESET << std::endl;
        std::cout << bcolors::RED << "########               ########## ########  ###    ###    ###    ###           ###          " << RESET << std::endl;

        // Show Options
        std::cout << bcolors::GREEN << "\n1. Encrypt" << RESET << std::endl;
        std::cout << bcolors::BLUEL << "\n2. Decrypt" << RESET << std::endl;
        std::cout << bcolors::YELLOW << "\n\n Option: ";
        std::cin >> option;

        std::string inputFile;
        int padding;

        std::cout << bcolors::WHITE << "\n[" << bcolors::GREEN << "+" << bcolors::WHITE << "]" << " Target name: ";
        std::cin >> inputFile;

        // Check if the file exists 
        std::ifstream file(inputFile);
        if (!file) {
            std::cout << bcolors::RED << "Error: File does not exist." << bcolors::WHITE << std::endl;
            return EXIT_FAILURE;
        }
        file.close();

        std::cout << bcolors::WHITE << "\n[" << bcolors::GREEN << "+" << bcolors::WHITE << "]" << " Padding *bit (0-∞): ";
        std::cin >> padding;

        // Check if padding is a valid positive integer
        if (std::cin.fail() || padding < 0) {
            std::cout << bcolors::RED << "Error: Invalid padding value. Padding must be a non-negative integer." << bcolors::WHITE << std::endl;
            return EXIT_FAILURE;
        }

        // Clear any leftover input in case of input errors
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');


        std::cout << bcolors::WHITE << "\n[" << bcolors::GREEN << "+" << bcolors::WHITE << "]" << " Passwd: ";
        SetStdinEcho(false); // Hide passwd while typing
        std::cin >> password;
        SetStdinEcho(true);
        std::cout << bcolors::ORANGE << "\n\n ";
        
        std::string hashedPassword = hashPassword(password); // Generate SHA-256 hash from passwd
        std::cout << bcolors::ORANGE;
        displayHashMaze(hashedPassword);

        LCRYPT lcrypt(hashedPassword); // Create LCRYPT object with passwd

        if (option == 1) {
            lcrypt.encrypt(inputFile, padding);
        } else if (option == 2) {
            lcrypt.decrypt(inputFile, padding);
        } else {
            std::cerr << "Opción no válida." << std::endl;
        }
        
    } else { // Execute argument mode on CLI
        int option = 0;
        std::string inputFile;
        std::string password;
        int padding = 0;

        int opt;
        bool show_help = false;

        // Process larger argument
        if (optind < argc) {
            std::string arg = argv[optind];
            if (arg == "--version") {
                std::cout << "C-LCRYPT version: " << VERSION;
                exit(0);
            }
        }

        while ((opt = getopt(argc, argv, "e:d:p:P:h")) != -1) {
            switch (opt) {
                case 'e': // Encrypt
                    option = 1;
                    inputFile = optarg;
                    break;
                case 'd': // Decrypt
                    option = 2;
                    inputFile = optarg;
                    break;
                case 'p': // Padding
                    padding = std::stoi(optarg);
                    break;
                    case 'P': // Password from file or plain text
                    if (isFile(optarg)) {  // If argument: file
                        std::ifstream passwordFile(optarg);
                        if (passwordFile) {
                            std::getline(passwordFile, password);  // Read first line
                            passwordFile.close();
                        } else {
                            std::cout << "Error: Cannot read password file." << std::endl;
                            return EXIT_FAILURE;
                        }
                    } else {  // Si no es un archivo, tomarlo como contraseña directa
                        password = optarg;
                    }
                    break;          
                case 'h': // Show help
                    show_help = true;
                    break;
                default: // Invalid option
                    show_help = true;
                    break;
            }
        }

        // Param error: show help
        if (show_help || option == 0 || inputFile.empty() || password.empty() || padding < 0) {
            showHelp();
            return (show_help) ? 0 : 1;
        }


        // Check if the file exists 
        std::ifstream file(inputFile);
        if (!file) {
            std::cout << bcolors::RED << "Error: File does not exist." << bcolors::WHITE << std::endl;
            return EXIT_FAILURE;
        }
        file.close();

        std::string hashedPassword = hashPassword(password);
        std::cout << bcolors::ORANGE;
        displayHashMaze(hashedPassword);

        LCRYPT lcrypt(hashedPassword); // Create LCRYPT object with passwd


        if (option == 1) {
            lcrypt.encrypt(inputFile, padding); 
        } else if (option == 2) {
            lcrypt.decrypt(inputFile, padding);
        } else {
            std::cerr << "No valid option." << std::endl;
            return 1;
        }
    }

    return 0;
}

// ####################################################################################################################################################################
// ####################################################################################################################################################################
// ####################################################################################################################################################################