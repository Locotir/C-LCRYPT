#include <iostream>                               // Provides functionalities for input and output (cin, cout).
#include <fstream>                                // Allows file stream handling (reading from and writing to files).
#include <vector>                                 // Implements the vector container for dynamic array handling.
#include <bitset>                                 // Enables the use of fixed-size bit sequences for binary manipulation.
#include <random>                                 // Contains functions and classes for random number generation.
#include <string>                                 // Provides the string class for handling text data.
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
#include <csignal>                                // Provides functions to handle asynchronous events (signals).
#include <cstdlib>                                // Provides functions for memory allocation, process control, and conversions.
#include <stdexcept>                              // Contains standard exception classes for error handling.
#include <future>                                 // Provides support for asynchronous programming and future/promise functionality.
#include <immintrin.h>                            // Includes definitions for AVX and SIMD operations (if supported).
#include <zstd.h>                                 // Provides functions for data compression and decompression using the Zstandard library.
#include <boost/iostreams/device/mapped_file.hpp> // Facilitates memory-mapped file I/O using the Boost Iostreams library.
#include <sodium.h>                               // Provides functions for cryptographic operations, including password hashing and encryption, from the libsodium library.

#define VERSION "v2.0.0\n"

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
long getAvailableRAM() {
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

    long requiredMemory = fileSize * (1 + (padding + 1) * 2) + 100 * 1024 * 1024; // Memory required + 500 MB
    long availableMemory = getAvailableRAM(); // Memmory aviable

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
    if (exePath.empty()) return;

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

// Archive the split files into a single tar file
void archiveFiles(const std::vector<std::string>& files, const std::string& inputFile) {
    // Extract directory and file name from inputFile
    std::filesystem::path inputPath(inputFile);
    std::string directory = inputPath.parent_path().string();
    std::string fileName = inputPath.filename().string();

    // Save the current working directory
    auto currentPath = std::filesystem::current_path();

    // Change to the directory where the files are located
    std::filesystem::current_path(directory);

    // Create the tar command
    std::string archiveName = fileName + ".tar";
    std::string command = "tar -cf " + archiveName;
    for (const auto& file : files) {
        std::filesystem::path filePath(file);
        command += " " + filePath.filename().string();
    }

    // Execute the tar command
    if (std::system(command.c_str()) != 0) {
        std::cerr << "Failed to create tar archive: " << archiveName << std::endl;
        // Change back to the original working directory
        std::filesystem::current_path(currentPath);
        return;
    }

    // Remove the part files
    for (const auto& file : files) {
        std::remove(file.c_str());
    }

    // Rename the .tar archive to the original input file name
    std::rename(archiveName.c_str(), fileName.c_str());

    // Change back to the original working directory
    std::filesystem::current_path(currentPath);
}

// Extract the split files from a tar archive
void extractFiles(const std::string& inputFile) {
    // Extract directory and file name from inputFile
    std::filesystem::path inputPath(inputFile);
    std::string directory = inputPath.parent_path().string();
    std::string fileName = inputPath.filename().string();

    // Save the current working directory
    auto currentPath = std::filesystem::current_path();

    // Change to the directory where the files are located
    std::filesystem::current_path(directory);

    std::string archiveName = fileName + ".tar";
    std::rename(fileName.c_str(), archiveName.c_str());

    std::string command = "tar -xf " + archiveName;
    if (std::system(command.c_str()) != 0) {
        std::cerr << "Failed to extract tar archive: " << archiveName << std::endl;
    }

    std::rename(archiveName.c_str(), fileName.c_str());

    // Change back to the original working directory
    std::filesystem::current_path(currentPath);
}

// Verify if a file was split into parts
bool containsPartTag(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }

    const size_t bufferSize = 512;
    char buffer[bufferSize] = {0};
    file.read(buffer, bufferSize);
    file.close();

    return std::string(buffer, file.gcount()).find("_part_") != std::string::npos;
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

            long availableMemory = getAvailableRAM();
            long requiredMemory = fileSize * (1 + (padding + 1) * 2) + 500 * 1024 * 1024;
            int numberOfParts = (requiredMemory + availableMemory - 1) / availableMemory; // Calculate the number of parts required
            long partSize = (fileSize + numberOfParts - 1) / numberOfParts; // Calculate the size of each part

            if (partSize <= 0) partSize = 1; // Ensure partSize is positive

            std::vector<std::string> partFiles = splitFile(inputFile, partSize); // Split the file into parts

            std::cout << bcolors::WHITE << " [" << bcolors::RED << "||" << bcolors::WHITE << "]"
                    << " File split into " << partFiles.size() << " parts due to insufficient RAM" << std::endl;

            processFiles(partFiles, password, padding, true); // Encrypt the parts

            archiveFiles(partFiles, inputFile); // Archive the encrypted parts into a single tar file

            std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "]"
                    << " Encrypted file saved as: " << inputFile << std::endl;

            exit(0); // Exit after encrypting the parts
        }

        // Continue with the nornal encryption process
        // Comprenssion
        std::cout << bcolors::WHITE << "\n\n[" << bcolors::BLUE << "%" << bcolors::WHITE << "]" << " Compressing..." << std::endl;
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
        std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "]" << " Encrypted file saved as: " << inputFile << std::endl;
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
            backup(inputFile); // Save backup file in case of failure

            std::cout << bcolors::YELLOW << "! The file was split due to insufficient RAM during encryption process." << std::endl;
            extractFiles(inputFile);

            // Collect the names of the split files
            std::vector<std::string> partFiles;
            for (char suffix1 = 'a'; suffix1 <= 'z'; ++suffix1) {
                for (char suffix2 = 'a'; suffix2 <= 'z'; ++suffix2) {
                    std::string partFilename = inputFile + "_part_" + suffix1 + suffix2;
                    std::ifstream partFile(partFilename);
                    if (!partFile) break;
                    partFiles.push_back(partFilename);
                }
            }

            // Decrypt the parts
            processFiles(partFiles, password, padding, false);

            // Concatenate the decrypted parts into a single file
            std::ofstream output(inputFile, std::ios::binary);
            if (!output) {
                std::cerr << "Failed to open output file: " << inputFile << std::endl;
                return;
            }

            for (const auto& file : partFiles) {
                std::ifstream input(file, std::ios::binary);
                if (!input) {
                    std::cerr << "Failed to open input file: " << file << std::endl;
                    continue;
                }
                output << input.rdbuf();
                input.close();
            }
            output.close();

            // Remove the part files
            for (const auto& file : partFiles) {
                std::remove(file.c_str());
            }

            std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "] Decrypted file saved as: " << inputFile << std::endl;

            // Delete backup file
            std::string backupFile = inputFile + ".backup";
            std::remove(backupFile.c_str());

            exit(0); // Exit after decrypting the parts
        }

        // Continue with the normal decryption process
        auto start = std::chrono::high_resolution_clock::now(); // Start timer
        auto fileSize = fs::file_size(inputFile);
        backup(inputFile); // Save backup file in case of failure

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
        std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "]" << " Decrypted file saved as: " << inputFile << std::endl;
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
    std::vector<char> readFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Can't open file.");
        }

        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<char> buffer(size);
        if (!file.read(buffer.data(), size)) {
            throw std::runtime_error("Error reading file.");
        }
        return buffer;
    }


    void writeFile(const std::string& filePath, const std::vector<char>& data) {
        std::ofstream file(filePath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Can't open file for writing.");
        }
        file.write(data.data(), data.size());
    }

    std::string formatFileSize(size_t size) { // Format to bytes
        std::ostringstream formattedSize;
        std::string sizeStr = std::to_string(size);
        
        for (size_t i = 0; i < sizeStr.length(); ++i) {
            if (i > 0 && (sizeStr.length() - i) % 3 == 0) {
                formattedSize << ".";
            }
            formattedSize << sizeStr[i];
        }
        return formattedSize.str();
    }

    void compressFile(const std::string& inputFile) {
        if (!fs::exists(inputFile) || (fs::is_directory(inputFile) && fs::is_empty(inputFile))) return;

        std::filesystem::path inputPath(inputFile);

        // Convert to absolute path
        std::filesystem::path absolutePath = fs::absolute(inputPath);
        std::string directory = absolutePath.parent_path().string();
        std::string fileName = absolutePath.filename().string();

        // Ensure the directory is valid and exists
        if (!fs::exists(directory)) {
            std::cerr << "Directory does not exist: " << directory << std::endl;
            return;
        }

        // Save the current working directory
        auto currentPath = fs::current_path();

        // Change to the directory where the file is located
        try {
            fs::current_path(directory);
        } catch (const fs::filesystem_error& e) {
            std::cerr << "Error changing directory: " << e.what() << std::endl;
            return;
        }

        std::string tarFile = fileName + ".tar";
        std::string zstdFile = fileName + ".zst";

        std::string tarCommand = "tar -cf " + tarFile + " " + fileName;
        
        if (std::system(tarCommand.c_str()) != 0 || !fs::exists(tarFile)) {
            fs::current_path(currentPath); // Restore the original working directory
            return;
        }

        auto originalSize = fs::file_size(tarFile);
        
        std::vector<char> fileData = readFile(tarFile);
        size_t compressedSize = ZSTD_compressBound(fileData.size());
        std::vector<char> compressedData(compressedSize);
        compressedSize = ZSTD_compress(compressedData.data(), compressedSize, fileData.data(), fileData.size(), 3);
        if (ZSTD_isError(compressedSize)) {
            fs::current_path(currentPath); // Restore the original working directory
            return;
        }

        compressedData.resize(compressedSize);
        writeFile(zstdFile, compressedData);
        fs::remove(tarFile);
        fs::remove_all(fileName); 
        fs::rename(zstdFile, fileName);

        // Restore the original working directory
        fs::current_path(currentPath);
        
        auto compressedFileSize = compressedData.size(); 
        int reductionPercentage = static_cast<int>(100.0 * (originalSize - compressedFileSize) / originalSize);
        std::cout << "    ↳ Reduced ~" 
                << std::fixed << std::setprecision(2) << reductionPercentage 
                << "% => " << std::fixed << std::setprecision(0) 
                << formatFileSize(compressedFileSize) << " total bits" << std::endl;
    }

    void decompressFile(const std::string& inputFile) {
        try {
            std::string zstdFile = inputFile + ".zst";
            std::string tarFile = inputFile + ".tar";

            fs::rename(inputFile, zstdFile);
            std::vector<char> compressedData = readFile(zstdFile);

            unsigned long long decompressedSize = ZSTD_getFrameContentSize(compressedData.data(), compressedData.size());
            if (decompressedSize == ZSTD_CONTENTSIZE_UNKNOWN) throw std::runtime_error("Incorrect password or padding");

            std::vector<char> decompressedData(decompressedSize);
            decompressedSize = ZSTD_decompress(decompressedData.data(), decompressedSize, compressedData.data(), compressedData.size());
            if (ZSTD_isError(decompressedSize)) throw std::runtime_error("Incorrect password or padding");

            writeFile(tarFile, decompressedData);
            fs::remove(zstdFile);

            // Get the directory of the input file
            std::string outputDir = fs::path(inputFile).parent_path().string();
            if (outputDir.empty()) outputDir = fs::current_path().string();
            if (!outputDir.empty() && !fs::exists(outputDir)) fs::create_directories(outputDir);

            std::string untarCommand = "tar -xf " + tarFile + " -C " + outputDir; // Extract to the original directory
            std::system(untarCommand.c_str());
            fs::remove(tarFile);
        } catch (...) {
            std::cerr << "\n\n[" << bcolors::RED << "!" << bcolors::WHITE << "]" << " Error decompressing:" << bcolors::RED << " Incorrect password or padding." << bcolors::WHITE << "\n    ↳ Backup file saved as: " << bcolors::GREEN << inputFile << ".backup" << std::endl;
            std::string zstdFile = inputFile + ".zst";
            fs::remove(zstdFile);
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
        std::array<uint8_t, 8> bitPatterns = {0, 1, 2, 3, 4, 5, 6, 7};
        std::default_random_engine generator(passwordHash + index);
        std::shuffle(bitPatterns.begin(), bitPatterns.end(), generator);

        uint8_t shuffledByte = 0;
        for (size_t j = 0; j < 8; ++j) {
            shuffledByte |= ((originalByte >> (7 - j)) & 1) << bitPatterns[j];
        }

        return shuffledByte;
    }

    static uint8_t reverseShuffleByte(uint8_t mixedByte, size_t passwordHash, size_t index) { // Thread Task
        std::array<uint8_t, 8> bitPatterns = {0, 1, 2, 3, 4, 5, 6, 7};
        std::default_random_engine generator(passwordHash + index);
        std::shuffle(bitPatterns.begin(), bitPatterns.end(), generator);

        uint8_t restoredByte = 0;
        for (size_t j = 0; j < 8; ++j) {
            restoredByte |= ((mixedByte >> bitPatterns[j]) & 1) << (7 - j);
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

    static std::array<uint8_t, SHA256_DIGEST_LENGTH> hashPassword(const std::string& password) {     // Hash passwd in unit8_t
        std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
        SHA256(reinterpret_cast<const uint8_t*>(password.c_str()), password.size(), hash.data());
        return hash; // Returns hash as an array
    }

    // Generate XOR Key string with passwd
    std::vector<uint8_t> generateXORKey(const std::array<uint8_t, SHA256_DIGEST_LENGTH>& passwordHash, size_t dataSize) {
        std::vector<uint8_t> key(dataSize);
        for (size_t i = 0; i < dataSize; ++i) {
            key[i] = passwordHash[i % SHA256_DIGEST_LENGTH]; // Only use Hash
        }
        return key; 
    }

    // Apply XOR Key in threads segments
    static void xorSegment(std::vector<uint8_t>& binaryData, const uint8_t* key, size_t keyLength, size_t start, size_t end) {
        for (size_t i = start; i < end; ++i) {
            binaryData[i] ^= key[i % keyLength]; // Apply XOR with Key
        }
    }

    void applyXOR(std::vector<uint8_t>& binaryData, const std::vector<uint8_t>& key) {
        size_t size = binaryData.size();
        unsigned int numCores = std::thread::hardware_concurrency();
        size_t segmentSize = (size + numCores - 1) / numCores; // Round
        std::vector<std::future<void>> futures;


        const uint8_t* keyPtr = key.data(); // Pointer2Key

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
    std::cout << "Usage: ./LCRYPT [options]\n"
              << "Options:\n"
              << "  -e <target>       Encrypt the specified file/folder\n"
              << "  -d <target>       Decrypt the specified file/folder\n"
              << "  -p <padding>      Specify the padding (0-∞)\n"
              << "  -P <password>     Specify the password\n"
              << "  --version         Show the current installed version\n"
              << "  -h                Display this help message\n"
              << "Examples:\n"
              << "  ./LCRYPT -e target -p 10 -P my_password\n"
              << "  ./LCRYPT -d target -p 10 -P my_password\n\n" 
              << bcolors::GREEN << "If executed without arguments, interactive mode will start." << std::endl;
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
                case 'P': // Passwd
                    password = optarg;
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
