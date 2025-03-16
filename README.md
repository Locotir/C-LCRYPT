![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white) [![Visual Studio Code](https://img.shields.io/badge/Visual%20Studio%20Code-0078d7.svg?style=for-the-badge&logo=visual-studio-code&logoColor=white)](https://code.visualstudio.com) [![Arch](https://img.shields.io/badge/Arch%20Linux-1793D1?logo=arch-linux&logoColor=fff&style=for-the-badge)](https://archlinux.org) [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/locotir)
# C-LCRYPT: Unbreakable Binary-Level Encryption
**=== Remake of [LCRYPT](https://github.com/Locotir/LCRYPT) on C++ | Gained +99.68% performance | All I/O operations runs on RAM now ===**


In today's digital landscape, protecting data at its core is essential. C-LCRYPT provides a robust encryption solution that secures data at the binary level, ensuring both integrity and confidentiality. Without the correct decryption keys, unauthorized access is effectively prevented.

### Description
C-LCRYPT is a C++ encryption program that encrypts files at the binary level with RAM-based I/O. The operational combination ensures that encrypted data is highly resistant to unauthorized decryption and reverse engineering. Even with access to the C-LCRYPT tool, brute-force attacks are computationally infeasible due to the vast key space and resource requirements. The encryption method also poses a significant challenge to potential advancements in quantum computing.

**Disclaimer**: C-LCRYPT does not embed any identifiable signature or trace that could be linked back to the tool or its author. The encryption algorithm is designed to be opaque, making it difficult to analyze or reverse-engineer without access to the source code.

### Installation & Run
```
git clone https://github.com/Locotir/C-LCRYPT
cd C-LCRYPT
sudo pacman -Syu gcc base-devel
g++ -std=c++17 -O3 -pipe -flto=$(nproc) -funroll-loops -fomit-frame-pointer -fno-plt -ffast-math -o C-LCRYPT C-LCRYPT.cpp -fopenmp
./C-LCRYPT
```

### AUR Arch
```
yay -S c-lcrypt
```

### Execution Parameters
```
Usage: ./C-LCRYPT [options]  
Options:  
  -e <target>       Encrypt the specified file/folder  
  -d <target>       Decrypt the specified file/folder  
  -p <padding>      Specify the padding (0-∞)  
  -P <password>     Specify the password <Plain/File>  
  --version         Show the current installed version  
  -h                Display this help message  

Examples:  
  ./C-LCRYPT -e target -p 10 -P my_password  
  ./C-LCRYPT -d target -p 10 -P my_password  

If executed without arguments, interactive mode will start.  
```

### Responsibility
The developer of C-LCRYPT assumes no responsibility for any misuse, damage, or issues arising from the use of this software. C-LCRYPT is provided solely for educational and research purposes. Users are fully responsible for ensuring their use of the software complies with all applicable laws and ethical standards.

# Program Operation
> [!NOTE]
> **[@]** Shuffle each Byte     
> **[@]** Reverse Binary Chain         
> **[@]** Bit Padding           
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




