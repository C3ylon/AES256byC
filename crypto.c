//#define _CRT_SECURE_NO_WARNINGS
//gcc .\filecrypto.c -o filecrypto -O3 -lshlwapi
#include <Windows.h>
#include <io.h>
//PathIsDirectory
#include<Shlwapi.h>
//if compile in vs2019, add next line:
//#pragma comment(lib, "shlwapi.lib")
#include <stdio.h>
#include "myaes.h"

#define READSIZE 1073741824 //1024 * 1024 * 1024

// unsigned char key[256];
uint8_t key[] = 
{
    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 
    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 
    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 
    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 
};
unsigned char* buff;
int if_encode = 0;
unsigned char filehead[] = { 0xE8, 0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3, 0xC0 };

unsigned char iv[] = 
{
    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 
    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 
};

int EncodeAndDecodeFile(const char* dirpath, const char* filename, int isfolder)
{
	char filepath[MAX_PATH];
	char filepathback[MAX_PATH];
	size_t chunks = 0;
	size_t szRead = 0;
	size_t szFile = 0;
	unsigned char align = 0;
	unsigned char alignbuff[16] = { 0x00 };

	strcpy(filepath, dirpath);
	if (isfolder)
	{
		strcat(filepath, "\\");
		strcat(filepath, filename);
	}

	FILE* fp = fopen(filepath, "rb+");
	if (fp)
	{
		if (if_encode)
		{
			fread(buff, 1, 8, fp);
			if ((*(size_t*)buff & 0xFFFFFFFFFFFFFF) != 0xC390909090E9E8)
			{
				_fseeki64(fp, 0, SEEK_END);
				szFile = _ftelli64(fp);
				align = szFile % 16;
				filehead[7] &= 0xF0;
				if (align)
				{
					fwrite(alignbuff, 1, 16 - align, fp);
					filehead[7] ^= align;
				}
				_fseeki64(fp, 0, SEEK_SET);
				strcpy(filepathback, filepath);
				strcat(filepath, ".tmp");

				FILE* tmp = fopen(filepath, "wb");
				if (tmp)
				{
					fwrite(filehead, 1, 8, tmp);
                    fwrite(iv, 1, 16, tmp);
                    struct AES_ctx aes;
                    AES_init_ctx(&aes, key, iv);

					while (szRead = fread(buff, 1, READSIZE, fp))
					{
                        AES_CBC_encrypt_buffer(&aes, buff, szRead);
						fwrite(buff, 1, szRead, tmp);
					}
					fclose(tmp);
				}
				fclose(fp);
				remove(filepathback);
				rename(filepath, filepathback);
				return 1;
			}
			fclose(fp);
		}
		else//decode
		{
			fread(buff, 1, 8, fp);
			if ((*(size_t*)buff & 0xFFFFFFFFFFFFFF) == 0xC390909090E9E8)
			{
				_fseeki64(fp, 0, SEEK_END);
				chunks = (_ftelli64(fp) - 24) / READSIZE;
				if((_ftelli64(fp) - 24) % READSIZE)
					chunks++;
				_fseeki64(fp, 8, SEEK_SET);
				align = *(buff + 7) & 0xF;
				strcpy(filepathback, filepath);
				strcat(filepath, ".tmp");
				FILE* tmp = fopen(filepath, "wb");
				if (tmp)
				{
                    struct AES_ctx aes;
                    fread(buff, 1, 16, fp);
                    memcpy(iv, buff, 16);
                    AES_init_ctx(&aes, key, iv);
					while (szRead = fread(buff, 1, READSIZE, fp))
					{
						chunks--;
						AES_CBC_decrypt_buffer(&aes, buff, szRead);
						if(chunks)
							fwrite(buff, 1, szRead, tmp);	
						else
						{
							if(align)
							{
								fwrite(buff, 1, szRead - 16 + align, tmp);
								break;
							}
							else
							{
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
				return 1;
			}
			fclose(fp);
		}
	}
	return 1;
}

int ListFiles(const char* dir)
{
	char dirNew[MAX_PATH];
	strcpy(dirNew, dir);
	if (!PathIsDirectoryA(dir))
	{
		EncodeAndDecodeFile(dir, "", FALSE);
	}
	else
	{
		strcat(dirNew, "\\*.*");
		struct __finddata64_t findData;
		intptr_t handle = _findfirst64(dirNew, &findData);
		if (handle == -1)
		{
			printf("[!]find path fail\n");
			return 0;
		}
		do
		{
			if (findData.attrib & _A_SUBDIR)
			{
				if (strcmp(findData.name, ".") == 0 || strcmp(findData.name, "..") == 0)
					continue;
				printf("[FOLDER]%s\n", findData.name);
				memset(dirNew, 0, MAX_PATH);
				strcpy(dirNew, dir);
				strcat(dirNew, "\\");
				strcat(dirNew, findData.name);
				ListFiles(dirNew);
			}
			else
			{
				printf("[FILE]%s\t%lld bytes\n", findData.name, findData.size);
				EncodeAndDecodeFile(dir, findData.name, TRUE);
			}
		} while (_findnext64(handle, &findData) == 0);
		_findclose(handle);
	}
	return 1;
}

int main(int argc, char *argv[])
{
	scanf("%d", &if_encode);
	// scanf("%s", key);
	buff = (unsigned char*)malloc(READSIZE);
	if (argv[1])
	{
		printf("[*]BEGIN\n");
		printf("[FILE_PATH]%s\n", argv[1]);
		ListFiles(argv[1]);
	}
	else
	{
		char dir[MAX_PATH];
		scanf("%s", dir);
		printf("[*]BEGIN\n");
		ListFiles(dir);
	}
	return 0;
}
