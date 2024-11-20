![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white) [![Visual Studio Code](https://img.shields.io/badge/Visual%20Studio%20Code-0078d7.svg?style=for-the-badge&logo=visual-studio-code&logoColor=white)](https://code.visualstudio.com) [![Arch](https://img.shields.io/badge/Arch%20Linux-1793D1?logo=arch-linux&logoColor=fff&style=for-the-badge)](https://archlinux.org) [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/locotir)
# C-LCRYPT: Unbreakable Binary-Level Encryption
**=== Remake of [LCRYPT](https://github.com/Locotir/LCRYPT) on C++ | Gained +99.68% performance | All I/O operations runs on RAM now ===**


In the digital age, securing data at its core is crucial. C-LCRYPT offers a revolutionary encryption solution that protects data at the binary level, ensuring integrity and confidentiality. Unauthorized access is impossible without the decryption keys.

### Description
C-LCRYPT encrypts files at the binary level, making data indecipherable without the correct keys. This method provides top-tier security, rendering manual decryption futile without the appropriate keys. C-LCRYPT-encrypted files resist reverse engineering due to their complexity. Each byte is shuffled randomly with a dynamic password with the option off add a random padding for each original bit, lenght defined by user. A suffled table of 0-255 corresponding to bytes are used to substitute each byte with another randomly. Finally an XOR Key string matching the same lenght of the total bits of the result is applied, all this steps results on complicating decryption attempts without the original tool. Even with the C-LCRYPT tool, brute force decryption is impractical due to the vast number of possible combinations and the required computational resources. The encryption's complexity remains a significant barrier, even against advancements in quantum computing.

**Disclaimer**: This tool does not leave any identifiable signature or trace that could be linked back to the tool or its author. The resulting encryption cannot be analyzed or reverse-engineered to understand the algorithm's nature without access to the program's source code.

### Installation & Run Arch
```
git clone https://github.com/Locotir/C-LCRYPT
cd C-LCRYPT
sudo pacman -Syu gcc openssl boost zlib zstd libsodium
g++ -O3 -pipe -fno-plt -o C-LCRYPT C-LCRYPT.cpp -lssl -lcrypto -lz -lboost_iostreams -mavx2 -lzstd -lsodium
./C-LCRYPT
```

### Execution Parameters
```
Usage: ./LCRYPT [options]
Options:
  -e <target>       Encrypt the specified file/folder
  -d <target>       Decrypt the specified file/folder
  -p <padding>      Specify the padding (0-∞)
  -P <password>     Specify the password
  -h                Display this help message
Examples:
  ./LCRYPT -e target -p 10 -P my_password
  ./LCRYPT -d target -p 10 -P my_password

If executed without arguments, interactive mode will start.
```

### I take NO responsibility in misuse
This program is provided for educational and research purposes only. The user assumes all responsibility for the use of the program. The developer is not responsible for any misuse, damage or problems caused by the program. It is strongly recommended to use this software in an ethical and legal manner.

# Program Operation
> [!NOTE]
> **[@]** Shuffle each Byte     
> **[@]** Reverse Binary Chain         
> **[@]** Fill with n bits between each original bit            
> **[@]** Substitute each byte with decimal Table (0-255):Psswd randomized           
> **[@]** XOR Key unique string applied as long as entire file bit string

# Logical Diagram

![LCRYPT-Diagrama drawio](https://github.com/user-attachments/assets/8acb9a81-a824-4f1a-9baa-2fbd3f72e825)

### Targets accepted
All type of files and folders (The larger, more RAM will consume): 

· **Text Files** -> .txt .docx .pdf...                                                                                                                                          
· **Data Files** -> .xls .xlsx .csv...                                                                                                                                          
. **Small Databases** -> .sql .db .mdb...                                                                                                                                          
· **Image Files** -> .png .jpg .gif...                                                                                                                                          
· **Audio Files** -> .mp3 .wav...                                                                                                                                          
· **Video Files** -> .mp4 .mkv .avi...                                                                                                                                          
· **Presentation Files** -> .ppt .pptx...                                                                                                                                          
· **Programming Files** -> .py .c .cpp...                                                                                                                                          
· **Config Files** -> .cfg .ini...                                                                                                                                          
· **Key Files** -> .key .cer                                                                                                                                          
· **Compressed Files** -> .zip .rar...


# Target example

![2024-10-28-140936_685x257_scrot](https://github.com/user-attachments/assets/24294530-7a86-400c-ba97-ac548091f0f7)

### After: |compresion\shuffling\reverse\padding\bytes substitution\XOR Key|:

![2024-10-28-141110_683x260_scrot](https://github.com/user-attachments/assets/f9bea13c-ee39-4477-b523-18955d493893)

### Console view

![2024-10-28-141046_754x706_scrot](https://github.com/user-attachments/assets/448e3e47-aa1c-429e-a697-367a50fbf337)
![2024-10-28-141202_745x651_scrot](https://github.com/user-attachments/assets/2367a0e2-4b93-4f2b-85c6-7b2bf654ea01)




