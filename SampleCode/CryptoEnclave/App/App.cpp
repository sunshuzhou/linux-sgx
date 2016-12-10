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
#define TOKEN_NAME "Enclave.token"

#define THREAD_NUM 3

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

// load_and_initialize_enclave():
//		To load and initialize the enclave     
sgx_status_t load_and_initialize_enclave(sgx_enclave_id_t *eid, struct sealed_buf_t *sealed_buf)
{
    sgx_status_t ret = SGX_SUCCESS;
    int retval = 0;
    int updated = 0;

    for( ; ; )
    {
        // Step 1: check whether the loading and initialization operations are caused by power transition.
        //		If the loading and initialization operations are caused by power transition, we need to call sgx_destory_enclave() first.
        if(*eid != 0)
        {
            sgx_destroy_enclave(*eid);
        }
	
        // Step 2: load the enclave
        // Debug: set the 2nd parameter to 1 which indicates the enclave are launched in debug mode
        ret = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
        if(ret != SGX_SUCCESS)
            return ret;

        // Save the launch token if updated
        if(updated == 1)
        {
            ofstream ofs(TOKEN_NAME, std::ios::binary|std::ios::out);
            if(!ofs.good())
            {
                cout<< "Warning: Failed to save the launch token to \"" <<TOKEN_NAME <<"\""<<endl;
            }
            else
                ofs << token;
        }

        // Step 3: enter the enclave to initialize the enclave
        //      If power transition occurs when the process is inside the enclave, SGX_ERROR_ENCLAVE_LOST will be returned after the system resumes.
        //      Then we can load and intialize the enclave again or just return this error code and exit to handle the power transition.
        //      In this sample, we choose to load and intialize the enclave again.
        ret = initialize_enclave(*eid, &retval, sealed_buf);
        if(ret == SGX_ERROR_ENCLAVE_LOST)
        {
            cout<<"Power transition occured in initialize_enclave()" <<endl;
            continue; // Try to load and initialize the enclave again
        }
        else
        {
            // No power transilation occurs.
            // If the initialization operation returns failure, change the return value.
            if(ret == SGX_SUCCESS && retval != 0)
            {
                ret = SGX_ERROR_UNEXPECTED;
                sgx_destroy_enclave(*eid);
            }
            break;
        }
    }
    return ret;
}

bool increase_and_seal_data_in_enclave()
{
    size_t thread_id = std::hash<std::thread::id>()(std::this_thread::get_id());
    sgx_status_t ret = SGX_SUCCESS;
    int retval = 0;
    sgx_enclave_id_t current_eid = 0;

    // Enter the enclave to increase and seal the secret data for 100 times.
    for(unsigned int i = 0; i< 50000; i++)
    {
        for( ; ; )
        {
            // If power transition occurs, all the data inside the enclave will be lost when the system resumes. 
            // Therefore, if there are some secret data which need to be backed up for recover, 
            // users can choose to seal the secret data inside the enclave and back up the sealed data.

            // Enter the enclave to increase the secret data and back up the sealed data
            rdlock(&lock_eid);
            current_eid = global_eid;
            rdunlock(&lock_eid);
            ret = increase_and_seal_data(current_eid, &retval, thread_id, &sealed_buf);

            if(ret == SGX_ERROR_ENCLAVE_LOST)
            {
                // SGX_ERROR_ENCLAVE_LOST indicates the power transition occurs before the system resumes.
                // Lock here is to make sure there is only one thread to load and initialize the enclave at the same time
                wtlock(&lock_eid);
                // The loading and initialization operations happen in current thread only if there is no other thread reloads and initializes the enclave before
                if(current_eid == global_eid)
                {
                    cout <<"power transition occured in increase_and_seal_data()." << endl;
                    // Use the backup sealed data to reload and initialize the enclave.
                    if((ret = load_and_initialize_enclave(&current_eid, &sealed_buf)) != SGX_SUCCESS)
                    {
                        ret_error_support(ret);
                        wtunlock(&lock_eid);
                        return false;
                    }
                    else
                    {
                        // Update the global_eid after initializing the enclave successfully
                        global_eid = current_eid;
                    }
                }
                else
                {
                    // The enclave has been reloaded by another thread. 
                    // Update the current EID and do increase_and_seal_data() again.
                    current_eid = global_eid;
                }
                wtunlock(&lock_eid);
            }
            else
            {
                // No power transition occurs
                break;
            }
        }
        if(ret != SGX_SUCCESS)
        {
            ret_error_support(ret);
            return false;
        }
        else if(retval != 0)
        {
            return false;
        }
    }
    return true;
}


void thread_func()
{
    if(increase_and_seal_data_in_enclave() != true)
    {
        abort();
    }
}

bool set_global_data()
{
    // Initialize the read/write lock.
    init_rwlock(&lock_eid);

    // Get the saved launch token.
    // If error occures, zero the token.
    ifstream ifs(TOKEN_NAME, std::ios::binary | std::ios::in);
    if(!ifs.good())
    {
        memset(token, 0, sizeof(sgx_launch_token_t));
    }
    else
    {
        ifs.read(reinterpret_cast<char *>(&token), sizeof(sgx_launch_token_t));
        if(ifs.fail())
        {
            memset(&token, 0, sizeof(sgx_launch_token_t));
        }
    }

    // Allocate memory to save the sealed data.
    uint32_t sealed_len = sizeof(sgx_sealed_data_t) + sizeof(uint32_t);
    for(int i = 0; i < BUF_NUM; i++)
    {
        sealed_buf.sealed_buf_ptr[i] = (uint8_t *)malloc(sealed_len);
        if(sealed_buf.sealed_buf_ptr[i] == NULL)
        {
            cout << "Out of memory" << endl;
            return false;
        }
        memset(sealed_buf.sealed_buf_ptr[i], 0, sealed_len);
    }
    sealed_buf.index = 0; // index indicates which buffer contains current sealed data and which contains the backup sealed data

    return true;
}

void release_source()
{
    for(int i = 0; i < BUF_NUM; i++)
    {
        if(sealed_buf.sealed_buf_ptr[i] != NULL)
        {
            free(sealed_buf.sealed_buf_ptr[i]);
            sealed_buf.sealed_buf_ptr[i] = NULL;
        }
    }
    fini_rwlock(&lock_eid);
    return;
}



# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
# define MAX_BUF_LEN 512
#include "sgx_urts.h"
//#include "App.h"
#include "Enclave_u.h"

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif


int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
//    char token_path[MAX_PATH] = {'.'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    ret = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if(ret != SGX_SUCCESS)
         return ret;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_NAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_NAME, sizeof(TOKEN_NAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_NAME, sizeof(TOKEN_NAME));
    }
    printf("TOKEN PATH = %s\n", token_path);
    FILE *fp = fopen(token_path, "rb");
    printf("#################%p\n", fp);
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    printf("ENCLAVE = %s\n", ENCLAVE_NAME);
    printf("DEBUG   = %d\n", SGX_DEBUG_FLAG);
    printf("TOKEN   = %s\n", token);
    printf("UPDATE  = %d\n", updated);

    ret = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("ERROR on Creating an envlace\n");
        if (fp != NULL) fclose(fp);
        return -1;
    }
    printf("TOKEN   = %s\n", token);

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}   

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);

}

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#define BUFFERSIZE 4096
int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
//        ret = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
//        if(ret != SGX_SUCCESS)
//            return ret;


/*
    if(!set_global_data())
    {
        release_source();
        cout << "Enter a character before exit ..." << endl;
        getchar();
        return -1;
    }

    sgx_status_t ret = load_and_initialize_enclave(&global_eid , NULL);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        release_source();
        cout << "Enter a character before exit ..." << endl;
        getchar();
        return -1;
    }
*/




    printf("hello1\n\n");
    sgx_status_t ret = SGX_SUCCESS;
    int retval = 0;
    int updated = 0;
    ret = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if(ret != SGX_SUCCESS)
         return ret;


/*
    int r = initialize_enclave();
    if(r < 0)
    {
       printf("App: error %#x, failed to create enclave.\n", r);
       return -1;
    }
*/

    printf("hello2\n\n");
//    char plaintext[MAX_BUF_LEN] = {'\0'};
//    printf("Outside the enclave - input  plaintext:  \"%s\"\n", plaintext);

    unsigned char buf[BUFFERSIZE+1] = {'\0'};
    size_t x;
    //FILE *fid = fopen("fox.txt", "r");
  //  FILE *fid = fopen("gutenberg/out.txt", "r");
//4300-0.txt
    int fid; 
    fid = open("gutenberg/4300-0.txt", O_RDONLY|O_LARGEFILE);

    if (fid == -1){
       return -1;
    }
	int i;

//lseek(fid, 0L, SEEK_END);
unsigned long int size = lseek(fid, 0L, SEEK_END);
lseek(fid,0,SEEK_SET);
//char plaintext[size+1];
char *plaintext = (char *) malloc(sizeof(char) * (size+1));
memset(plaintext, '\0', sizeof(plaintext));


/*
fseek(fid, 0L, SEEK_END);
unsigned long int size = ftell(fid);
printf("%lu\n", size);
rewind(fid);
char plaintext[size+1];
memset(plaintext, '\0', sizeof(plaintext));
i = 0;
*/
off_t chunk = 0;
size_t readlen;
printf("XXXXXXXXXXXXXX\n");
//while ( chunk < size )
int j = 0;
do
{
// 1048576
   readlen=read(fid,buf,4096);
//printf("%zu %d\n", strlen(buf), readlen);
   //readnow=read(fid,((char *)plaintext)+chunk,4096);

 //  printf("%s", buf);
   if (readlen < 0 )
   {
      close (fid);
      return -1;
   }
enclave_copy(global_eid, buf, strlen((char *)buf)+1);
memset(buf,'\0',sizeof(buf));
j++;
//if (j == 2)
//break;
//   enclave_copy(global_eid, buf, strlen(buff)+1);
//   chunk=chunk+readnow;
} while (readlen == sizeof(buf)-1);

if (close(fid)) 
{
   return -1;
}


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
printf("%d %d %d %d %d\n", strlen((char*)plaintext), sizeof(plaintext), chunk, sizeof(buf), readlen);
printf("%d\n", size);
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

/*
    // Initialize the global data
    if(!set_global_data())
    {
        release_source();
        cout << "Enter a character before exit ..." << endl;
        getchar();
        return -1;
    }

    // Load and initialize the signed enclave
    // sealed_buf == NULL indicates it is the first time to initialize the enclave.
    sgx_status_t ret = load_and_initialize_enclave(&global_eid , NULL);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        release_source();
        cout << "Enter a character before exit ..." << endl;
        getchar();
        return -1;
    }

    cout << "****************************************************************" << endl;
    cout << "Demonstrating Power transition needs your cooperation." << endl
        << "Please take the following actions:" << endl
        << "    1. Enter a character;" << endl
        << "    2. Manually put the OS into a sleep or hibernate state;" << endl
        << "    3. Resume the OS from that state;" << endl
        << "Then you will see the application continues." << endl;
    cout << "****************************************************************" << endl;
    cout << "Now enter a character ...";
    getchar();

    // Create multiple threads to calculate the sum
    thread trd[THREAD_NUM];
    for (int i = 0; i< THREAD_NUM; i++)
    {
        trd[i] = thread(thread_func);
    }
    for (int i = 0; i < THREAD_NUM; i++)
    {
        trd[i].join();
    }

    // Release resources
    release_source();

    // Destroy the enclave
    sgx_destroy_enclave(global_eid);

    cout << "Enter a character before exit ..." << endl;
    getchar();
*/
    return 0;
}

