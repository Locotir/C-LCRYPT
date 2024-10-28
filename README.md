![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white) [![Visual Studio Code](https://img.shields.io/badge/Visual%20Studio%20Code-0078d7.svg?style=for-the-badge&logo=visual-studio-code&logoColor=white)](https://code.visualstudio.com) [![Arch](https://img.shields.io/badge/Arch%20Linux-1793D1?logo=arch-linux&logoColor=fff&style=for-the-badge)](https://archlinux.org) [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/locotir)
# C-LCRYPT: Unbreakable Binary-Level Encryption
**Remake of [LCRYPT](https://github.com/Locotir/LCRYPT)**

In the digital age, securing data at its core is crucial. C-LCRYPT offers a revolutionary encryption solution that protects data at the binary level, ensuring integrity and confidentiality. Unauthorized access is impossible without the decryption keys.

### Description
C-LCRYPT encrypts files at the binary level, making data indecipherable without the correct keys. This method provides top-tier security, rendering manual decryption futile without the appropriate keys. C-LCRYPT-encrypted files resist reverse engineering due to their complexity. Each byte is shuffled randomly with a dynamic password with the option off add a random padding for each original bit, lenght defined by user. A suffled table of 0-255 corresponding to bytes are used to substitute each byte with another randomly. Finally an XOR Key string matching the same lenght of the total bits of the result is applied, all this steps results on complicating decryption attempts without the original tool. Even with the C-LCRYPT tool, brute force decryption is impractical due to the vast number of possible combinations and the required computational resources. The encryption's complexity remains a significant barrier, even against advancements in quantum computing.

**Disclaimer**: This tool does not leave any identifiable signature or trace that could be linked back to the tool or its author. The resulting encryption cannot be analyzed or reverse-engineered to understand the algorithm's nature without access to the program's source code.

### Installation & Run Arch
```
git clone https://github.com/Locotir/C-LCRYPT
cd C-LCRYPT
sudo pacman -Syu gcc openssl boost zlib zstd
g++ -O3 -o C-LCRYPT C-LCRYPT.cpp -lssl -lcrypto -lz -lboost_iostreams -mavx2 -lzstd
./C-LCRYPT
```
