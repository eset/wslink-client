// -*- encoding: utf8 -*-
// 
// Copyright (c) 2021 ESET spol. s r.o.
// Author: Vladislav Hrčka <vladislav.hrcka@eset.com>
// See LICENSE file for redistribution.

#define assymetric_timeout 30000
#define modulus_len 256
#define key_len 32
#define iv_len 16
#define hello_len 0xf0
#define answer_len 0xf0
#define symmetric_encrypt_send_offset  0x22c0
#define receive_wrapper_offset 0x1d10
#define symmetric_receive_decrypt_offset 0x2410
char* module_sig = "0123456789abcdef0123456789abcdef";
char* module_key = "0123456789abcdef0123456789abcdef";
char null_iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

struct tls_context {
	SOCKET sock;
	char key[key_len];
	char iv[iv_len];
};

struct module_id {
	int constant_id;
	char module_signature[0x20];
};

struct handshake_answer {
	char key[key_len];
	char iv[iv_len];
	char random_padding[0xC0];
};

struct wslink_functions {
	int (*symmetric_encrypt_send) (struct tls_context* cnt, void *buff, int buff_len);
	int (*receive_wrapper) (SOCKET s, char *buf, int len, int timeout);
	int (*symmetric_receive_decrypt) (struct tls_context* cnt, void *buff, int buff_len);
};

struct wslink_module {
	char* data;
	int len;
};

int init_wslink_functions(struct wslink_functions* wsf);
SOCKET init_connection(char* ip, int port);
int handshake(struct wslink_functions*, struct tls_context* cnt, char* private_key);
int send_module(struct wslink_functions* wsf, struct tls_context* cnt);
RSA * createRSA(unsigned char * key, int isPublic);
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
char* get_private_key();
void clear_socket(SOCKET s);
int get_plugin(struct wslink_module* wsm);
