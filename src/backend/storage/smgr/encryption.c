/*-------------------------------------------------------------------------
 *
 * encryption.c
 *	  This code handles encryption and decryption of data.
 *
 * Encryption is done by extension modules loaded by encryption_library GUC.
 * The extension module must register itself and provide a cryptography
 * implementation. Key setup is left to the extension module.
 *
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/storage/smgr/encryption.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/pg_control.h"
#include "storage/bufpage.h"
#include "storage/encryption.h"
#include "miscadmin.h"
#include "fmgr.h"
#include "port.h"

bool encryption_enabled = false;
bool have_encryption_provider = false;
EncryptionRoutines encryption_hooks;

/*
 * Hook function for encryption providers. The first library to call this
 * function gets to provide encryption capability.
 */
void
register_encryption_module(char *name, EncryptionRoutines *enc)
{
	if (!have_encryption_provider)
	{
		elog(DEBUG1, "Registering encryption module %s", name);
		encryption_hooks = *enc;
		have_encryption_provider = true;
	}
}

/*
 * Encrypts a fixed value into *buf to verify that encryption key is correct.
 * Caller provided buf needs to be able to hold at least ENCRYPTION_SAMPLE_SIZE
 * bytes.
 */
void
sample_encryption(char *buf)
{
	char tweak[TWEAK_SIZE];
	int i;
	for (i = 0; i < TWEAK_SIZE; i++)
		tweak[i] = i;

	encrypt_block("postgresqlcrypt", buf, ENCRYPTION_SAMPLE_SIZE, tweak);
}

/*
 * Encrypts one block of data with a specified tweak value. Input and output
 * buffer may point to the same location. Size of input must be at least
 * ENCRYPTION_BLOCK bytes. Tweak value must be TWEAK_SIZE bytes.
 *
 * All zero blocks are not encrypted or decrypted to correctly handle relation
 * extension.
 *
 * Must only be called when encryption_enabled is true.
 */
void
encrypt_block(const char *input, char *output, Size size, const char *tweak)
{
	Assert(size >= ENCRYPTION_BLOCK);
	Assert(encryption_enabled);

	if (IsAllZero(input, size))
	{
		if (input != output)
			memset(output, 0, size);
	}
	else
		encryption_hooks.EncryptBlock(input, output, size, tweak);
}

/*
 * Decrypts one block of data with a specified tweak value. Input and output
 * buffer may point to the same location. Tweak value must match the one used
 * when encrypting.
 *
 * Must only be called when encryption_enabled is true.
 */
void
decrypt_block(const char *input, char *output, Size size, const char *tweak)
{
	Assert(size >= ENCRYPTION_BLOCK);
	Assert(encryption_enabled);

	if (IsAllZero(input, size))
	{
		if (input != output)
			memset(output, 0, size);
	}
	else
		encryption_hooks.DecryptBlock(input, output, size, tweak);
}

/*
 * Initialize encryption subsystem for use. Must be called before any
 * encryptable data is read from or written to data directory.
 */
void
setup_encryption()
{
	char *filename;

	if (encryption_library_string == NULL || encryption_library_string[0] == '\0')
		return;

	/* Try to load encryption library */
	filename = pstrdup(encryption_library_string);

	canonicalize_path(filename);

	/* Make encryption libraries loading behave as if loaded via s_p_l */
	process_shared_preload_libraries_in_progress = true;
	load_file(filename, false);
	process_shared_preload_libraries_in_progress = false;

	ereport(DEBUG1,
			(errmsg("loaded library \"%s\" for encryption", filename)));
	pfree(filename);

	if (have_encryption_provider)
	{
		encryption_enabled = encryption_hooks.SetupEncryption();
		if (encryption_enabled)
		{
			if (!IsBootstrapProcessingMode())
				elog(LOG, "data encryption performed by %s", encryption_library_string);
		}
		else
			elog(FATAL, "data encryption could not be initialized");
	}
	else
		elog(ERROR, "Specified encryption library %s did not provide encryption hooks.", encryption_library_string);
}

