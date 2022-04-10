//#define _CRT_SECURE_NO_WARNINGS
//gcc .\filecrypto.c -o filecrypto -O3 -lshlwapi

//PathIsDirectory
//#include<Shlwapi.h>
//if compile in vs2019, add next line:
//#pragma comment(lib, "shlwapi.lib")

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <io.h>
#include <string.h>
#include "myaes.h"

#define READSIZE 1073741824 //1024 * 1024 * 1024
#define KEYSIZE 32
#define IVSIZE 16

#ifndef MAX_PATH
  #define MAX_PATH 260
#endif

#define GENIV(i) ((short*)(void*)&iv)[i] = (short)rand()

uint8 key[KEYSIZE] = { 0 };
uint8 iv[IVSIZE] = { 0 };

uint8 buff[READSIZE] = { 0 };

int if_encode = 0;

uint8 filehead[] = { 0xE8, 0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3, 0xC0 };

void geniv(void)
{
    srand((unsigned int)time(NULL));
    GENIV(0); GENIV(1); GENIV(2); GENIV(3);
    GENIV(4); GENIV(5); GENIV(6); GENIV(7);
}

void EncodeAndDecodeFile(const char* dirpath, const char* filename)
{
    char filepath[MAX_PATH];
    char filepathback[MAX_PATH];
    size_t chunks = 0, szRead = 0, szFile = 0;
    uint8 align = 0;
    uint8 alignbuff[16] = { 0 };
    strcpy(filepath, dirpath);
    if (filename[0] != '\0') {
        strcat(filepath, "\\");
        strcat(filepath, filename);
    }
    FILE* fp = fopen(filepath, "rb+");
    if (fp) {
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
                strcpy(filepathback, filepath);
                strcat(filepath, ".tmp");
                FILE* tmp = fopen(filepath, "wb");
                if (tmp) {
                    fwrite(filehead, 1, 8, tmp);
                    fwrite(iv, 1, 16, tmp);
                    struct AES_ctx aes;
                    AES_init_ctx(&aes, key, iv);
                    while ((szRead = fread(buff, 1, READSIZE, fp))) {
                        AES_CBC_encrypt_buffer(&aes, buff, szRead);
                        fwrite(buff, 1, szRead, tmp);
                    }
                    fclose(tmp);
                }
                fclose(fp);
                remove(filepathback);
                rename(filepath, filepathback);
                return;
            }
            fclose(fp);
        }// if(if_encode)
        else {
            fread(buff, 1, 8, fp);
            if ((*(size_t*)buff & 0xFFFFFFFFFFFFFF) == 0xC390909090E9E8) {
                _fseeki64(fp, 0, SEEK_END);
                chunks = (_ftelli64(fp) - 24) / READSIZE;
                if((_ftelli64(fp) - 24) % READSIZE)
                    chunks++;
                _fseeki64(fp, 8, SEEK_SET);
                align = *(buff + 7) & 0xF;
                strcpy(filepathback, filepath);
                strcat(filepath, ".tmp");
                FILE* tmp = fopen(filepath, "wb");
                if (tmp) {
                    struct AES_ctx aes;
                    fread(buff, 1, 16, fp);
                    memcpy(iv, buff, 16);
                    AES_init_ctx(&aes, key, iv);
                    while ((szRead = fread(buff, 1, READSIZE, fp))) {
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
                remove(filepathback);
                rename(filepath, filepathback);
                return;
            }
            fclose(fp);
        }// if(if_encode)
    }// if(fp)
    return;
}

void TraversalFiles(const char* dir)
{
    struct _stat64 sbuff;
    if(_stat64(dir, &sbuff) == -1) {
        printf("[!]find file or folder path fail\n");
        return;
    } 
    if(sbuff.st_mode & _S_IFREG) {
        printf("[*]file size: %I64d bytes\n", sbuff.st_size);
        EncodeAndDecodeFile(dir, "");
    }
    else if(sbuff.st_mode & S_IFDIR) {
        char dirNew[MAX_PATH];
        strcpy(dirNew, dir);
        strcat(dirNew, "\\*.*");
        struct __finddata64_t findData;
        intptr_t handle = _findfirst64(dirNew, &findData);
        if (handle == -1) {
            printf("[!]find path fail\n");
            return;
        }
        do {
            if(findData.attrib & _A_SUBDIR) {
                if (strcmp(findData.name, ".") == 0 || strcmp(findData.name, "..") == 0) {
                    continue;
                }
                printf("[FOLDER]%s\n", findData.name);
                memset(dirNew, 0, MAX_PATH);
                strcpy(dirNew, dir);
                strcat(dirNew, "\\");
                strcat(dirNew, findData.name);
                TraversalFiles(dirNew);
            }
            else {
                printf("[FILE]%s\t%I64d bytes\t", findData.name, findData.size);
                clock_t start, end;
                start = clock();
                EncodeAndDecodeFile(dir, findData.name);
                end = clock();
                printf("time: %.2fs\n", (double)(end - start) / CLOCKS_PER_SEC);
            }
        } while (_findnext64(handle, &findData) == 0);
        _findclose(handle);
    }
}

void genkey(void)
{
    int i = 0;
    uint8 tmp;
    // while(i < KEYSIZE) {
    //     if((tmp = getchar()) != '\n') {
    //         key[i++] = tmp;
    //     }
    // }
    while(getchar() != '\n');
    while((tmp = getchar()) == '\n');
    do {
        key[i++] = tmp;
    } while(i < KEYSIZE && (tmp = getchar()) != '\n');
    if(i == KEYSIZE) {
        while(getchar() != '\n');
    }
    else {
        int j = -1, len = i;
        while(i < KEYSIZE) {
            j = (j + 1) % len;
            key[i++] = key[j];
        }
    }
}

int main(int argc, char *argv[])
{
    if(argv[1] == NULL) {
        printf("[!]Missing parameter: file_path\n");
        return -1;
    }
    scanf("%d", &if_encode);
    genkey();
    clock_t start, end;
    start = clock();
    printf("[*]BEGIN\n");
    printf("[FILE_PATH]%s\n", argv[1]);
    TraversalFiles(argv[1]);
    end = clock();
    printf("[+]total time is %.2fs\n", (double)(end - start) / CLOCKS_PER_SEC);
    system("pause");
    return 0;
}
