/*-------------------------------------------------------------------------
 *
 * encryption.h
 *	  Full database encryption support
 *
 *
 * Portions Copyright (c) 1996-2015, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/encryption.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "lib/ilist.h"

#define ENCRYPTION_BLOCK 16
#define TWEAK_SIZE 16

extern PGDLLIMPORT bool encryption_enabled;


void setup_encryption(void);
void sample_encryption(char *buf);
void encrypt_block(const char *input, char *output, Size size,
		const char *tweak);
void decrypt_block(const char *input, char *output, Size size,
		const char *tweak);

typedef bool (*SetupEncryption_function) ();
typedef void (*EncryptBlock_function) (const char *input, char *output,
		Size size, const char *tweak);
typedef void (*DecryptBlock_function) (const char *input, char *output,
		Size size, const char *tweak);

/*
 * Hook functions to register an encryption provider.
 */
typedef struct {
	dlist_node node;
	/*
	 * Will be called at system initialization time immediately after loading
	 * the encryption module. Return value indicates if encryption is
	 * successfully initialized. Returning false will result in a FATAL error.
	 */
	SetupEncryption_function SetupEncryption;
	/*
	 * Encrypt/decrypt one block of data. Input and output buffers may point
	 * to the same buffer. Buffer alignment is not guaranteed. Buffer size
	 * will be at least 16 bytes, but is not guaranteed to be a multiple of 16.
	 */
	EncryptBlock_function EncryptBlock;
	DecryptBlock_function DecryptBlock;
} EncryptionRoutines;

void register_encryption_module(char *name, EncryptionRoutines *provider);

#endif   /* ENCRYPTION_H */
