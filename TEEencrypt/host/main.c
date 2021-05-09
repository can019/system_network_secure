/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#define MAX 1000
int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[MAX] = {0,};
	char ciphertext[MAX] = {0, };
	int len = MAX;
	char *plainextention = ".txt";
	char *cipherextention = ".E";
	char *keyextention = ".K";
	char *decrptextion = "_decr";
	int key;
	int arr_key[1] = {-1};
	
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));


	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	/*op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;*/
	
	/* command line flag check */
	if (argc==3){
		if(strcmp(argv[1], "-e")==0){
			printf("========================Encryption========================\n");
			char *filename = argv[2];
			if(strstr(filename, plainextention)==NULL){
				printf("Wrong file extention\n");
				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				return -1;
			}

			FILE* fp = fopen(filename,"r");
			if(fp==NULL){
				printf("No such file exists\n");
				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				return -1;
			}
			fseek(fp, 0, SEEK_END);
			if(ftell(fp)>=MAX){
				printf("WARN :: MAX SIZE = 1000B\n");
				printf("Encrpted text will generate only 1000B");
			}
			fseek(fp, 0, SEEK_SET);
			fread(plaintext, 1, len, fp);
			fclose(fp);
			printf("%s", plaintext);

			/* Encryption starts */

			op.params[0].tmpref.buffer = plaintext;
			op.params[0].tmpref.size = len;
			memcpy(op.params[0].tmpref.buffer, plaintext, len);

			op.params[1].tmpref.buffer = arr_key;
			op.params[1].tmpref.size = sizeof(arr_key);
			memcpy(op.params[1].tmpref.buffer, arr_key, sizeof(arr_key));
			

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			memcpy(arr_key, op.params[1].tmpref.buffer, sizeof(arr_key));
			printf("Ciphertext : %.*s\n",strlen(ciphertext), ciphertext);
			//printf("key :: %d",arr_key[0]);
			/* Encryption done */
			
			/* Save ciphertext starts */
			char *pure_filename = strtok(filename,".");
			char text_filename[strlen(pure_filename+2)];
			sprintf(text_filename,"%s%s", pure_filename, cipherextention);

			fp = fopen(text_filename, "w");;
			fwrite(ciphertext, strlen(ciphertext), 1, fp);
			fclose(fp);
			/* Save ciphertext done */

			/* Save key starts */
			char key_filename[strlen(pure_filename+2)];
			sprintf(key_filename,"%s%s", pure_filename, keyextention);
			key = arr_key[0];

			fp = fopen(key_filename, "w");;
			fprintf(fp, "%d", key);
			fclose(fp);
			/* Save key done */
		}
	}
	else if(argc == 4){
		if(strcmp(argv[1], "-d")==0){
			char *cipher_filename = argv[2];
			char *key_filename = argv[3];
			printf("========================Decryption========================\n");
			if(strstr(cipher_filename, cipherextention)==NULL){
				printf("Wrong file extention :: cipherextention\n");
				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				return -1;
			}

			FILE* fp = fopen(cipher_filename,"r");
			if(fp==NULL){
				printf("No such file exists\n");
				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				return -1;
			}
			
			fread(ciphertext, 1, len, fp);
			fclose(fp);
			printf("%s", ciphertext);
			
			/* key */
			if(strstr(key_filename, keyextention)==NULL){
				printf("Wrong file extention :: cipherextention\n");
				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				return -1;
			}

			fp = fopen(key_filename,"r");
			if(fp==NULL){
				printf("No such file exists\n");
				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				return -1;
			}
			
			fscanf(fp,"%d", &key);
			fclose(fp);
			//printf("%d", key);
			arr_key[0] = key;
			/*printf("%d\n", key);
			printf("%d\n, %d\n", arr_key[0], sizeof(arr_key));*/
			/* key */

			op.params[0].tmpref.buffer = plaintext;
			op.params[0].tmpref.size = len;
			memcpy(op.params[0].tmpref.buffer, ciphertext, len);

			op.params[1].tmpref.buffer = arr_key;
			op.params[1].tmpref.size = sizeof(arr_key);
			memcpy(op.params[1].tmpref.buffer, arr_key, sizeof(arr_key));

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
			memcpy(plaintext, op.params[0].tmpref.buffer, len);
			printf("Plaintext : %.*s\n",strlen(plaintext), plaintext);

			char *pure_filename = strtok(cipher_filename,".");
			char text_filename[strlen(pure_filename+9)];
			sprintf(text_filename,"%s%s%s", pure_filename, decrptextion, plainextention);

			fp = fopen(text_filename, "w");;
			fwrite(plaintext, strlen(plaintext), 1, fp);
			fclose(fp);
		}
	}
	else{
		printf("wrong input :: given argc is %d\n",argc);
	}
	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
