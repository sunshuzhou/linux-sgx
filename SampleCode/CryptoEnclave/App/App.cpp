/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



// App.cpp : Define the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>
#include "sgx_key.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "rwlock.h"
#include "ErrorSupport.h"

#define ENCLAVE_NAME "libenclave.signed.so"
#define TOKEN_NAME   "Enclave.token"
#define BUFFERSIZE   4096
#define SHA256_LEN   32
// Global data
sgx_enclave_id_t global_eid = 0;
sgx_launch_token_t token = {0};
rwlock_t lock_eid;
struct sealed_buf_t sealed_buf;

using namespace std;

// Ocall function
void print(const char *str)
{
    cout<<str;
}


int main(int argc, char* argv[])
{
   (void)argc;
   (void)argv;

   int fid;
   if(argc == 2)
   {
      fid = open(argv[1], O_RDONLY|O_LARGEFILE);
      if (fid == -1)
      {
         printf("USAGE: %s FILE_PATH\n", argv[0]);
         return (-1);
      }
   }
   else
   {
      printf("USAGE: %s FILE_PATH\n", argv[0]);
      return (-1);
   }

   int updated = 0;
   if(SGX_SUCCESS != sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL))
   {
      printf("App: error, failed to create enclave.\n");
      return (-1);
   }

   unsigned char buf[BUFFERSIZE+1] = {'\0'};
   size_t len;

   do
   {
      len=read(fid,buf,BUFFERSIZE);
      if (len < 0 )
      {
         close (fid);
         return (-1);
      }
      gen_sha256(global_eid, buf, len + 1);
      memset(buf,'\0',sizeof(buf));
   } 
   while (len == sizeof(buf) - 1);

   memset(buf,'\0',sizeof(buf));
   if (close(fid)) 
   {
      return (-1);
   }

   unsigned char sha256_out[SHA256_LEN] = {'\0'};
   get_sha256(global_eid, sha256_out, SHA256_LEN);
   printf("    App.cpp: Created sha256 hash: \"");
   int i;
   for(i = 0; i < 32; i++)
   {
         printf("%02x", sha256_out[i]);
   }
   printf("\"\n");

/*
   fid = open(argv[1], O_RDONLY|O_LARGEFILE);

   do
   {
      len=read(fid,buf,BUFFERSIZE);
      if (len < 0 )
      {
         close (fid);
         return (-1);
      }
      gen_sha256(global_eid, buf, len + 1);
      memset(buf,'\0',sizeof(buf));
   }

   memset(buf,'\0',sizeof(buf));
   if (close(fid)) 
   {
      return (-1);
   }
*/

/*
    do {
	printf("%d\n", i);
        x = fread(((unsigned char *)plaintext) + chunk, 1, 1048576, fid);
	i++;
	printf("%d\n", i);
       //       printf("%s", buf);
       //err = hmac_process(&hmac, buf, (unsigned long)x);
      // if (err != 0) {
        //                fclose(in);
          //              return err;
            //    }
       
//       memset(buf, '\0', sizeof(buf));
 	chunk = chunk + x;
    } while (x == sizeof(buf));

    if (fclose(fid) != 0) {
       return -1;
    }
*/

//for(i = 0; i < size+1; i++)
//printf("%s", plaintext);
//printf(" %d %d %d\n",  chunk, sizeof(buf), readlen);
//printf("%d\n", size);
//    enclave_copy(global_eid, plaintext, strlen(plaintext)+1);

/*
    gen_sha256(global_eid, plaintext, strlen(plaintext)+1);
    memset(plaintext, 0, MAX_BUF_LEN);
    unsigned char ciphertext[MAX_BUF_LEN] = {'\0'};
    printf("\nOutside the enclave - output ciphertext: \"%s\"\n", ciphertext);
    get_sha256(global_eid, ciphertext, MAX_BUF_LEN);
    printf("Outside the enclave - output ciphertext: \"");
    unsigned char *i = ciphertext;
    while(*i){
         printf("%x", *i);
         *i++;
    }
    printf("\"\n");
    printf("\n\n\n\n\n");
*/
//    memset(plaintext, 0, MAX_BUF_LEN);
//    gen_hmac_sha256(global_eid, plaintext, strlen(plaintext)+1);

//   const sgx_key_request_t *key_request;
//   sgx_key_128bit_t *key;
//   sgx_status_t ret1 = sgx_get_key(key_request, key);



/*
    char secret[MAX_BUF_LEN] = "My secret string";
    printf("\nDump secret: Copy a secret from the untrusted code to the enclave\n");
    printf("Outside the enclave - input  secret: \"%s\"\n", secret);
    dump_secret(global_eid, secret, strlen(secret)+1);

    printf("Outside the enclave - input  secret: \"%s\"\n", secret);
    memset(secret, 0, MAX_BUF_LEN);

    printf("\nGet  secret: Copy a secret from the enclave to the untrusted code\n");
    printf("Outside the enclave - output secret: \"%s\"\n", secret);

    get_secret(global_eid, secret, MAX_BUF_LEN);
    printf("Outside the enclave - output secret: \"%s\"\n", secret);
*/
/*
    sgx_sealed_data_t secretData = {0};
    uint32_t add_mac_txt_size = 0;
    uint32_t txt_encrypt_size = strlen(secret)+1;
    uint32_t secretDataSize = sgx_calc_sealed_data_size(add_mac_txt_size, txt_encrypt_size);
*/



  
    if(SGX_SUCCESS != sgx_destroy_enclave(global_eid))
    {
        printf("App: error, failed to destroy enclave.\n");
    }    

    return (0);
}

