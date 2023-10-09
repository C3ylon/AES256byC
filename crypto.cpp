//#define _CRT_SECURE_NO_WARNINGS
//gcc .\filecrypto.c -o filecrypto -O3 -lshlwapi

//PathIsDirectory
//#include<Shlwapi.h>
//if compile in vs2019, add next line:
//#pragma comment(lib, "shlwapi.lib")

#include <iostream>
#include <string>
#include <iomanip>
#include <time.h>
#include <sys/stat.h>
#include "myaes.h"
#include "stdio.h"
constexpr auto READSIZE = 1021 * 1024 * 1024;
constexpr auto KEYSIZE = 32;
constexpr auto IVSIZE = 16;

#ifndef MAX_PATH
  #define MAX_PATH 260
#endif


uint8 key[KEYSIZE];
uint8 iv[IVSIZE];

uint8 buff[READSIZE];
uint8 alignbuff[IVSIZE];

static bool if_encode = 0;

uint8 filehead[] = { 0xE8, 0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3, 0xC0 };

static void geniv(void) {
    srand((unsigned int)time(nullptr));
    auto geniv = [](const int i) { ((short*)&iv)[i] = (short)rand(); };
    geniv(0); geniv(1); geniv(2); geniv(3);
    geniv(4); geniv(5); geniv(6); geniv(7);
}

static void EncodeAndDecodeFile(const char *dirpath)
{
    std::string filepath = dirpath;
    std::string filepathbackup;
    size_t chunks = 0, szRead = 0, szFile = 0;
    uint8 align = 0;

    FILE* fp = fopen(filepath.c_str(), "rb+");
    if(!fp) {
        throw std::string("\n[!]open file : ") + filepath + " fall";
    }

    if (if_encode) {
        geniv();
        fread(buff, 1, 8, fp);
        if ((*(size_t*)buff & 0xFFFFFFFFFFFFFF) != 0xC390909090E9E8) {
            _fseeki64(fp, 0, SEEK_END);
            szFile = _ftelli64(fp);
            align = szFile % 16;
            filehead[7] &= 0xF0;
            if (align) {
                fwrite(alignbuff, 1, 16 - align, fp);
                filehead[7] ^= align;
            }
            _fseeki64(fp, 0, SEEK_SET);
            filepathbackup = filepath;
            filepath += ".tmp";
            FILE* tmp = fopen(filepath.c_str(), "wb");
            if (tmp) {
                fwrite(filehead, 1, 8, tmp);
                fwrite(iv, 1, IVSIZE, tmp);
                struct AES_ctx aes;
                AES_init_ctx(&aes, key, iv);
                while((szRead = fread(buff, 1, READSIZE, fp))) {
                    AES_CBC_encrypt_buffer(&aes, buff, szRead);
                    fwrite(buff, 1, szRead, tmp);
                }
                fclose(tmp);
            }
            fclose(fp);
            remove(filepathbackup.c_str());
            rename(filepath.c_str(), filepathbackup.c_str());
            return;
        }
        fclose(fp);
    } else {
        fread(buff, 1, 8, fp);
        if ((*(size_t*)buff & 0xFFFFFFFFFFFFFF) == 0xC390909090E9E8) {
            _fseeki64(fp, 0, SEEK_END);
            chunks = (_ftelli64(fp) - 24) / READSIZE;
            if((_ftelli64(fp) - 24) % READSIZE)
                chunks++;
            _fseeki64(fp, 8, SEEK_SET);
            align = *(buff + 7) & 0xF;
            filepathbackup = filepath;
            filepath += ".tmp";
            FILE* tmp = fopen(filepath.c_str(), "wb");
            if (tmp) {
                struct AES_ctx aes;
                fread(buff, 1, IVSIZE, fp);
                memcpy(iv, buff, IVSIZE);
                AES_init_ctx(&aes, key, iv);
                while((szRead = fread(buff, 1, READSIZE, fp))) {
                    chunks--;
                    AES_CBC_decrypt_buffer(&aes, buff, szRead);
                    if(chunks) {
                        fwrite(buff, 1, szRead, tmp);
                    } 
                    else {
                        if(align) {
                            fwrite(buff, 1, szRead - 16 + align, tmp);
                            break;
                        } 
                        else {
                            fwrite(buff, 1, szRead, tmp);
                            break;
                        }
                    }
                }
                fclose(tmp);
            }
            fclose(fp);
            remove(filepathbackup.c_str());
            rename(filepath.c_str(), filepathbackup.c_str());
            return;
        }
        fclose(fp);
    }// if(if_encode)

    return;
}

template <typename T>
void TraversalFiles(const char *dir, T FileOp) {
    struct _stat64 sbuff;
    if(_stat64(dir, &sbuff) == -1) {
        throw "\n[!]find file or folder path fail";
    }
    // input path is a sigle file
    if(sbuff.st_mode & _S_IFREG) {
        std::cout << "[*]file size: " << sbuff.st_size << "bytes\n";
        FileOp(dir);
    }
    // input path is a folder
    else if(sbuff.st_mode & S_IFDIR) {
        std::string dirNew = std::string(dir) + "\\*.*";
        struct __finddata64_t findData;
        intptr_t handle = _findfirst64(dirNew.c_str(), &findData);
        if (handle == -1) {
            throw "\n[!]find path fail";
        }
        do {
            if(findData.attrib & _A_SUBDIR) {
                auto foldername = [&](const char *s)
                    { return std::string(findData.name) == s; };
                if (foldername(".") || foldername("..")) {
                    continue;
                }
                std::cout << "[FOLDER]" << findData.name << "\n";
                dirNew = std::string(dir) + "\\" + findData.name;
                TraversalFiles(dirNew.c_str(), FileOp);
            } else {
                std::cout << "[FILE]" << findData.name << "\t" << findData.size << " bytes\t";
                clock_t start, end;
                start = clock();
                std::string fullpath = std::string(dir) + "\\" + findData.name;
                FileOp(fullpath.c_str());
                end = clock();
                std::cout << "time: " << (double)(end - start) / CLOCKS_PER_SEC << "s\n";
            }
        } while(_findnext64(handle, &findData) == 0);
        _findclose(handle);
    }
}

static void genkey() {
    std::string s;
    std::cin >> s;
    auto len = s.size();
    for(int i = 0; i < KEYSIZE; i++) {
        key[i] = s.at(i%len);
    }
}

static void cmdfunc(int argc, char *argv[], clock_t &start) {
    if(argc < 2) {
        throw "\n[!]Missing parameter: file_path";
    }
    std::cout << "[FILE_PATH]" << argv[1] << "\n";
    std::cout << std::flush;
    std::cin >> if_encode;
    genkey();
    start = clock();
    TraversalFiles(argv[1], EncodeAndDecodeFile);
}

int main(int argc, char *argv[]) {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);
    std::cout << std::fixed << std::setprecision(2);

    clock_t start, end;

    auto endfn = [&](const char *s) {
        end = clock();
        std::cout << s << "\n";
        std::cout << "[+]total time is " << (double)(end - start) / CLOCKS_PER_SEC << "s\n";
    };

    std::cout << "[*]BEGIN\n";
    try {
        cmdfunc(argc, argv, start);
    } catch(const char *e) {
        endfn(e);
    } catch(const std::string &e) {
        endfn(e.c_str());
    }
    std::cout << std::flush;
    system("pause");
    return 0;
}