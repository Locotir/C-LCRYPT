#include <iostream>                               // Provides functionalities for input and output (cin, cout).
#include <fstream>                                // Allows file stream handling (reading from and writing to files).
#include <vector>                                 // Implements the vector container for dynamic array handling.
#include <random>                                 // Contains functions and classes for random number generation.
#include <string>                                 // Provides the string class for handling text data.
#include <set>                                    // Implements the std::set container for storing unique elements in a sorted order.
#include <sys/stat.h>                             // Defines the struct stat and the stat() function to obtain file information (used for checking file existence and metadata).
#include <algorithm>                              // Offers a collection of algorithms (e.g., sorting, searching).
#include <sstream>                                // Facilitates string stream operations for manipulating strings as streams.
#include <filesystem>                             // Introduces facilities for file system operations (directories, paths).
#include <cstring>                                // Provides functions for handling C-style strings (e.g., strcpy, strlen).
#include <limits>                                 // Defines characteristics of fundamental data types (e.g., min/max values).
#include <termios.h>                              // Provides an interface for terminal I/O attributes (for controlling terminal settings).
#include <unistd.h>                               // Contains miscellaneous symbolic constants and types, including POSIX operating system API.
#include <chrono>                                 // Provides utilities for measuring time and duration.
#include <sys/sysinfo.h>                          // Contains definitions for obtaining system information (e.g., memory usage, uptime).
#include <omp.h>                                  // Provides support for multi-platform shared memory multiprocessing programming in C++.
#include <array>                                  // Implements the array container for fixed-size array handling.
#include <cstdint>                                // Provides fixed-width integer types like int32_t, uint64_t, etc.
#include <cstdio>                                 // Offers standard input/output functions like printf and scanf.
#include <csignal>                                // Provides functions to handle asynchronous events (signals).
#include <cstdlib>                                // Provides functions for memory allocation, process control, and conversions.
#include <stdexcept>                              // Contains standard exception classes for error handling.
#include <future>                                 // Provides support for asynchronous programming and future/promise functionality.
#include <fcntl.h>                                // Defines constants and functions for file control operations, such as open(), O_RDONLY, etc.
#include <sys/mman.h>                             // Provides memory-mapping functions such as mmap(), munmap(), and memory protection constants like PROT_READ and MAP_PRIVATE.

#define VERSION "v4.0.0\n"

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


// +++++++++++++++++++++++++++++++++++++++++++++++++++++++ SHA 256 class ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Define SHA-256 digest length constant
constexpr size_t SHA256_DIGEST_LENGTH = 32;

// Standalone SHA-256 helper function: Rotate right
uint32_t rotr(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32 - n));
}

// Standalone SHA-256 implementation returning binary digest
std::array<uint8_t, SHA256_DIGEST_LENGTH> sha256(const std::string &input) {
    // Compression function constants
    uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Initial hash values
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // Pre-processing: Padding
    std::vector<uint8_t> msg(input.begin(), input.end());
    msg.push_back(0x80);
    while ((msg.size() * 8) % 512 != 448) {
        msg.push_back(0x00);
    }
    uint64_t bit_len = input.size() * 8;
    for (int i = 7; i >= 0; i--) {
        msg.push_back((bit_len >> (i * 8)) & 0xff);
    }

    // Process message in 512-bit (64-byte) blocks
    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[chunk + i * 4] << 24) | (msg[chunk + i * 4 + 1] << 16) |
                   (msg[chunk + i * 4 + 2] << 8) | (msg[chunk + i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    // Construct binary digest in big-endian order
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest;
    auto to_big_endian = [](uint32_t value, uint8_t* buffer) {
        buffer[0] = (value >> 24) & 0xFF;
        buffer[1] = (value >> 16) & 0xFF;
        buffer[2] = (value >> 8) & 0xFF;
        buffer[3] = value & 0xFF;
    };
    to_big_endian(h0, &digest[0]);
    to_big_endian(h1, &digest[4]);
    to_big_endian(h2, &digest[8]);
    to_big_endian(h3, &digest[12]);
    to_big_endian(h4, &digest[16]);
    to_big_endian(h5, &digest[20]);
    to_big_endian(h6, &digest[24]);
    to_big_endian(h7, &digest[28]);
    return digest;
}
std::string toHexString(const std::array<uint8_t, 32>& digest) {
    std::ostringstream oss;
    for (uint8_t byte : digest) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::pair<int, int> countLettersAndDigits(const std::string& hexHash) {
    int letters = 0;
    int digits = 0;
    for (char c : hexHash) {
        if (std::isalpha(c)) {
            letters++;
        } else if (std::isdigit(c)) {
            digits++;
        }
    }
    return {letters, digits};
}
// --------------------------------------------------------------------------------------------------------------------------------

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

    long requiredMemory = fileSize * (1 + padding) * 2 + (5 * 1024 * 1024); // Memory required + 5 MB
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
    try {
        std::filesystem::path exePath = std::filesystem::canonical("/proc/self/exe");
        return exePath.string();
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error getting executable path: " << e.what() << std::endl;
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


size_t computeNumericHash(const std::string &input) { // Hash -> int (32-bit & 64-bit compatible)
    auto digest = sha256(input); // Compute the SHA-256 hash of the input string
    uint32_t hashValue = 0;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashValue = hashValue * 31u + digest[i];
    }
    return static_cast<size_t>(hashValue);
}

// -=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=-

namespace fs = std::filesystem;


//=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=
class LCRYPT {
public:
    LCRYPT(const std::string& hashedPassword) 
        : password(hashedPassword) {
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
            long requiredMemory = fileSize * 2 * (1 + padding) + (5 * 1024 * 1024);
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
        size_t firstPasswordHash = computeNumericHash(firstRound);
        shuffleBytes(binary, firstPasswordHash);
        

        // Padding *bit
        std::cout << bcolors::WHITE << "\n[" << bcolors::GREEN << "*" << bcolors::WHITE << "]" << " Adding Padding *bit";
        applyPadding(binary, padding, secondRound); // Padding for each bit
        

        // Byte to Table byte reference
        std::cout << bcolors::WHITE << "\n[" << bcolors::VIOLET << "<->" << bcolors::WHITE << "]" << " Byte to Decimal Reference";
        size_t thirdPasswordHash = computeNumericHash(thirdRound);
        auto substitutionTable = generateByteSubstitutionTable(thirdPasswordHash);
        byteSubstitution(binary, substitutionTable);
        
        // XOR Key
        std::cout << bcolors::WHITE << "\n[" << bcolors::RED << "^" << bcolors::WHITE << "]" << " Applying XOR Key";
        std::array<uint8_t, SHA256_DIGEST_LENGTH> hashedPassword = hashPassword(fourthRound); 
        auto xorKey = generateXORKey(hashedPassword, binary.size());
        applyXOR(binary, xorKey);

        // Finish & save
        saveToFile(inputFile, binary);
        std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "]" << " Encrypted target saved as: " << inputFile << std::endl;


    }

    void decrypt(const std::string& inputFile, int padding) {
        // Check if the file was split into parts
        if (containsPartTag(inputFile)) {
            backup(inputFile); // Create a backup

            std::cout << bcolors::YELLOW << "! The file was split due to insufficient RAM during encryption process." << std::endl;
           
            std::vector<std::string> partFiles = extractFiles(inputFile); // Extract the parts (e.g., file_part_aa, file_part_ab, file_part_ac, ...)

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
        size_t thirdPasswordHash = computeNumericHash(thirdRound);
        auto substitutionTable = generateByteSubstitutionTable(thirdPasswordHash);
        auto inverseTable = generateInverseSubstitutionTable(substitutionTable);
        byteSubstitutionDecrypt(binary, inverseTable);
        

        // Padding *bit
        std::cout << bcolors::WHITE << "\n[" << bcolors::GREEN << "*" << bcolors::WHITE << "]" << " Removing Padding *bit";
        removePadding(binary, padding);
        

        // Unshuffle
        std::cout << bcolors::WHITE << "\n[" << bcolors::RED << "@" << bcolors::WHITE << "]" << " Unshuffling inverted bytes";
        size_t firstPasswordHash = computeNumericHash(firstRound);
        reverseByteShuffle(binary, firstPasswordHash);
        

        // Save to decompress
        saveToFile(inputFile, binary);

        // Dele backup file
        std::string backupFile = inputFile + ".backup";
        std::remove(backupFile.c_str());

        // Finish
        std::cout << bcolors::WHITE << "\n\n[" << bcolors::GREEN << "=" << bcolors::WHITE << "]" << " Decrypted target saved as: " << inputFile << std::endl;
    }

//=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=-#=

private:
    std::string password;
    bool noCompression;
    std::string firstRound, secondRound, thirdRound, fourthRound;

    std::string hashPasswordRounds(const std::string& password) {
        const size_t ROUNDS = 10000; // number of iterations
        std::array<uint8_t, 32> currentHash = sha256(password);

        // Iterate on rounds
        for (size_t i = 0; i < ROUNDS; ++i) {
            std::string hexHash = toHexString(currentHash);
            std::string toHash = hexHash + password; // Combine with actual passwd
            currentHash = sha256(toHash);
        }

        return toHexString(currentHash);
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


// ++++++++++++++++++++++++++++++++++++++++++++++++++++ Load File Bits To RAM +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
std::vector<uint8_t> loadFileAsBits(const std::string& filePath) {
    // Open the file
    int fd = open(filePath.c_str(), O_RDONLY);
    if (fd == -1) {
        throw std::runtime_error("Error opening the file.");
    }

    // Get the size of the file
    struct stat fileStats;
    if (fstat(fd, &fileStats) == -1) {
        close(fd);
        throw std::runtime_error("Error getting the file size.");
    }

    size_t fileSize = fileStats.st_size;

    // Map the file into memory
    uint8_t* data = (uint8_t*)mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        close(fd);
        throw std::runtime_error("Error mapping the file.");
    }

    // Create a vector with the mapped data
    std::vector<uint8_t> result(data, data + fileSize);

    // Unmap the file and close the file descriptor
    munmap(data, fileSize);
    close(fd);

    return result;
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

    std::array<uint8_t, 256> generateByteSubstitutionTable(size_t passwordHash) {
        std::array<uint8_t, 256> table;
        std::iota(table.begin(), table.end(), 0); // table: 0-255

        std::default_random_engine generator(passwordHash); // Use hash as seed
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

    static std::array<uint8_t, SHA256_DIGEST_LENGTH> hashPassword(const std::string& password) {  // Hash password to uint8_t array
        return sha256(password);
    }

    // Generate XOR Key string with password hash | non repetitive
    std::vector<uint8_t> generateXORKey(const std::array<uint8_t, SHA256_DIGEST_LENGTH>& passwordHash, size_t dataSize) {
        std::vector<uint8_t> key;
        key.reserve(dataSize);

        std::array<uint8_t, SHA256_DIGEST_LENGTH> currentHash = passwordHash;
        
        while (key.size() < dataSize) {
            // Convert currentHash to a std::string
            std::string hashStr(reinterpret_cast<const char*>(currentHash.data()), SHA256_DIGEST_LENGTH);
            // Compute SHA-256 of hashStr
            currentHash = sha256(hashStr);
            // Append the new hash to the key
            for (uint8_t byte : currentHash) {
                if (key.size() < dataSize) {
                    key.push_back(byte);
                } else {
                    break;
                }
            }
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
void increaseMemoryUsage(std::string& toHash, const std::string& hexHash) {
    // Use the hash as a seed for random number generation
    std::seed_seq seed(hexHash.begin(), hexHash.end());
    std::mt19937 rng(seed);

    // Define the character set (letters and digits)
    std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Set the buffer size to exactly 1 MB in bytes
    size_t bufferSize = 1024 * 1024; 

    // Create buffer
    std::vector<char> buffer(bufferSize);

    // Fill the buffer with random characters from the charset
    for (size_t i = 0; i < bufferSize; ++i) {
        std::uniform_int_distribution<int> charDist(0, charset.size() - 1);
        buffer[i] = charset[charDist(rng)];
    }

    // Append the buffer data to the string to increase its size
    toHash += std::string(buffer.begin(), buffer.end());
}

// Function to hash a password multiple times while increasing memory usage
std::string hashPassword(const std::string& password, size_t rounds = 1) {
    // Calculate the initial hash of the password
    std::array<uint8_t, 32> currentHash = sha256(password);
    
    // Perform multiple rounds of hashing, with increasing memory usage each time
    for (size_t i = 0; i < rounds; ++i) {
        // Convert the current hash to a hexadecimal string
        std::string hexHash = toHexString(currentHash);
        
        // Increase memory usage in each iteration using the current hash as a seed
        increaseMemoryUsage(hexHash, hexHash);
        
        // Count the number of letters and digits in the hexadecimal hash
        auto [letters, digits] = countLettersAndDigits(hexHash);
        
        // Create a new string for the next hash by appending the counts of letters and digits
        std::string toHash = hexHash + std::to_string(letters) + std::to_string(digits);
        
        // Recalculate the hash of the new string
        currentHash = sha256(toHash);
    }

    // Return the final hash as a hexadecimal string
    return toHexString(currentHash);
}


// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Display  Help Message +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void showHelp() {
    std::cout << "Usage: c-lcrypt [options]\n"
              << "Options:\n"
              << "  -e <target>       Encrypt the specified file\n"
              << "  -d <target>       Decrypt the specified file\n"
              << "  -p <padding>      Specify the padding (0-∞)\n"
              << "  -P <password>     Specify the password <Plain/File>\n"
              << "  --version         Show the current installed version\n"
              << "  -h                Display this help message\n"
              << "Examples:\n"
              << "  c-lcrypt -e target -p 10 -P my_password\n"
              << "  c-lcrypt -d target -p 10 -P my_password\n"
              << bcolors::GREEN << "If executed without arguments, interactive mode will start." << std::endl;
} 

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ Chech File +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
bool isFile(const std::string& path) { // Chech if -P (passwd) is a file
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);  // verify if file exists
}


// ====================================================================== M A I N =====================================================================================
int main(int argc, char *argv[]) {

    auto start = std::chrono::high_resolution_clock::now(); // Start timer
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

        while ((opt = getopt(argc, argv, "e:d:p:P:zh")) != -1) {
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
                    if (isFile(optarg)) {
                        std::ifstream passwordFile(optarg);
                        if (passwordFile) {
                            std::getline(passwordFile, password);
                            passwordFile.close();
                        } else {
                            std::cout << "Error: Cannot read password file." << std::endl;
                            return EXIT_FAILURE;
                        }
                    } else {
                        password = optarg;
                    }
                    break;
                case 'h': // Show help
                    show_help = true;
                    break;
                default:
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

        auto end = std::chrono::high_resolution_clock::now(); // Stop timer
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        long seconds = duration / 1000;
        long milliseconds = duration % 1000;
        long minutes = seconds / 60;
        seconds %= 60;

        std::cout << bcolors::WHITE << "\n" << minutes << "m | " << seconds << "s | " << milliseconds << "ms\n\n";
    }

    return 0;
}

// ####################################################################################################################################################################
// ####################################################################################################################################################################
// ####################################################################################################################################################################