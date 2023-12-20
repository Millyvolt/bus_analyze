
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <io.h>
#include <fcntl.h>
#include <stdlib.h>


#include "can_parser.h"


char filebuf[FILEBUF_LEN_MAX] = {0}, *filebufcopy, tmp_str[10] = {0};
char filename[PATH_LEN_MAX] = {0}, path[PATH_LEN_MAX] = DEFAULT_FILEPATH;
unsigned char inversions = DEFAULT_INVERSIONS, bitscountmask = DEFAULT_BITSCOUNT;
unsigned long long bitmask = DEFAULT_BITMASK;
int openflags = O_RDONLY | O_TEXT, fd;
ID_count id_cnt[ID_CNT_MAX] = {0};



int main()
{

        printf("Enter full path and filename or type 'd' - default,\ndefault path is '%s'\n", path);      
        if(gets(filename) == NULL) { perror("gets"); sleep(1); exit(1); } // осторожно - gets не проверяет длину введенной строки - возможная уязвимость
        if(!(strcmp(filename, "d") == 0 || strcmp(filename, "D") == 0))
        {
            memset(path, 0, PATH_LEN_MAX);
            strcpy(path, filename);
        }

        fd = open(path, openflags);
        if(fd == -1) { perror("open"); sleep(1); exit(1); }

        long flen = filelength(fd);
#ifdef DEBUG_CNFG
        printf("The file is %ld bytes long.\n", flen);
#endif  //DEBUG_CNFG

#ifdef RELEASE_CNFG
        printf("Enter invertions count:\n");
        if(gets(tmp_str) == NULL) { perror("gets"); sleep(1); exit(1); }
		inversions = atoi(tmp_str);

		printf("Enter bitmask in decimal format:\n");
        if(gets(tmp_str) == NULL) { perror("gets"); sleep(1); exit(1); }
		bitmask = atoi(tmp_str);

		printf("Enter bitmask bits count:\n");
        if(gets(tmp_str) == NULL) { perror("gets"); sleep(1); exit(1); }
		bitscountmask = atoi(tmp_str);
#endif  //RELEASE_CNFG


        int readcnt = 0, bytescnt = 0;
        char str_tmp[READBYTES_CNT + 1];

        while(bytescnt < flen)
        {
            readcnt = read(fd, str_tmp, READBYTES_CNT);
            if(readcnt == -1) { perror("read file"); sleep(1); exit(1); }
			strcat(filebuf, str_tmp);
            if(readcnt < READBYTES_CNT)
			{
#ifdef DEBUG_CNFG
                printf("warning: read %d bytes, less than %d\n", readcnt, READBYTES_CNT);
				bytescnt += readcnt;
#endif  //DEBUG_CNFG
				break;
			}
            bytescnt += readcnt;
        }
        
#ifdef DEBUG_CNFG
        printf("strlen(filebuf) = %d\n", strlen(filebuf));
        printf("bytescnt = %d\n", bytescnt);
#endif  //DEBUG_CNFG  
        bytescnt = 0;

		filebufcopy = strdup(filebuf);

        char *pdelim = " \t\n", *ptoken = strtok(filebufcopy, pdelim);
		int i;

		// read all IDs and their count
        while(ptoken != NULL)
        {
			if(strcmp("SFF", ptoken) == 0 || strcmp("EFF", ptoken) == 0)
			{
				ptoken = strtok(NULL, pdelim);

				i = 0;
				while(id_cnt[i].frame_id != NULL)
				{
					if(strcmp(id_cnt[i].frame_id, ptoken) == 0)
					{
						id_cnt[i].id_count++;
						break;
					}
					i++;
				}
				if(id_cnt[i].frame_id == NULL)
				{
					id_cnt[i].frame_id = (char *)malloc(sizeof(char) * strlen(ptoken));
					strcpy(id_cnt[i].frame_id, ptoken);
					id_cnt[i].id_count++;
					ptoken = strtok(NULL, pdelim);
					id_cnt[i].bytes_count = atoi(ptoken);
				}
			}

        	ptoken = strtok(NULL, pdelim);
        }

		free(filebufcopy);


		char *pend;
		unsigned char **carray;
			
		i = 0;
		while(id_cnt[i].frame_id != NULL)
		{	//dinamic memory allocation for two-dimensional array to store frames for current ID
			carray = (unsigned char **)malloc(sizeof(unsigned char *) * id_cnt[i].id_count);
			for(int j = 0; j < id_cnt[i].id_count; j++)
				*(carray + j) = (unsigned char *)malloc(sizeof(unsigned char) * id_cnt[i].bytes_count);

			filebufcopy = strdup(filebuf);		//need every time allocate for strtok()
			ptoken = strtok(filebufcopy, pdelim);

			//get array of frames for current ID
			for(int n = 0; n < id_cnt[i].id_count; n++)
			{
				while(strcmp(ptoken, id_cnt[i].frame_id) != 0)
					ptoken = strtok(NULL, pdelim);

				ptoken = strtok(NULL, pdelim);		//pass number bytes in frame, we read it earlier
				
				for(int m = 0; m < id_cnt[i].bytes_count; m++)
				{
					ptoken = strtok(NULL, pdelim);
					if(*ptoken == '0')
					{
						ptoken++;
						if(*ptoken == 'x')
						{
							ptoken++;
							carray[n][m] = strtol(ptoken, &pend, 16);
						}
					}
				}
			}

			unsigned long long u64array[id_cnt[i].id_count], u64mask, state;
			memset(u64array, 0, sizeof(unsigned long long) * id_cnt[i].id_count);

			//transform array for bit masking
			for(int k = 0; k < id_cnt[i].id_count; k++)
				for(int l = 0; l < id_cnt[i].bytes_count; l++)
					u64array[k] += (unsigned long long)carray[k][l] << l*8;

			//check bit sequencies
			u64mask = bitmask;
			unsigned char inv_left = inversions;
			for(int bitidx = 0; bitidx < 64 - (bitscountmask - 1); bitidx++)
			{
				u64mask = bitmask << bitidx;
				state = u64array[0] & u64mask;
				for(int idx = 1; idx < id_cnt[i].id_count; idx++)
				{
					if(state != (u64array[idx] & u64mask))
					{
						if(inv_left == 0)
						{
							inv_left = inversions;
							break;
						}
						inv_left--;
						state = u64array[idx] & u64mask;
					}
				}
				if(inv_left == 0)	//bytes and bits numeration starting from 1 - for result indication
					printf("sequence match: ID:%s, byte:%d, bit:%d\n", id_cnt[i].frame_id, bitidx/8+1, bitidx%8+1);
				inv_left = inversions;
			}

			i++;

			//error - some signal
			// for(int j = 0; j < id_cnt[i].id_count; j++)
			// 	free(*(carray + j));
			free(carray);
			free(filebufcopy);
		}


		memset(id_cnt, 0, ID_CNT_MAX * sizeof(ID_count));
		if(close(fd) == -1)	{ perror("close"); sleep(1); exit(1); }
		printf("\n(bytes and bits numeration starting from 1)\n\n");
		printf("Press Enter to exit\n");
		gets(tmp_str);

    return 0;
}


