NTSTATUS dh_generate(char* srv_pubkey, size_t srv_pubkey_len, char** pubkey, uint32_t* pubkey_len, char** secret, uint32_t* secret_len)
{
	char* dh_prime = (char*)"\xF5\x1F\xFB\x3C\x62\x91\x86\x5E\xCD\xA4\x9C\x30\x71\x2D\xB0\x7B";
	char* dh_gen = (char*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03";
	size_t dh_prime_len = 64;// 16;
	size_t dh_gen_len = 64;// 16;
	BCRYPT_KEY_HANDLE dh_key;
	PUCHAR pubkey_blob = NULL;
	ULONG pubkey_blob_len = 0;

	size_t key_blob_len = sizeof(BCRYPT_DH_KEY_BLOB) + dh_prime_len + dh_gen_len;
	ULONG server_public_key_blob_size = sizeof(BCRYPT_DH_KEY_BLOB) + dh_prime_len + dh_gen_len + srv_pubkey_len;
	unsigned char* server_public_key_blob = NULL;
	BCRYPT_DH_KEY_BLOB* public_key_blob_struct = NULL;
	BCRYPT_KEY_HANDLE hPublickey = NULL;
	BCRYPT_SECRET_HANDLE hAgreedSecret = NULL;

	if (!pubkey || !pubkey_len || !secret || !secret_len) {
		printf("bad input arguments to dh_generate\n");
		return -1;
	}

	if (dh_prime_len != dh_gen_len) {
		printf("error - dh_prime length does not match dh_generator length\n");
		return -1;
	}

	//create Diffie-Hellman parameter structure
	size_t dh_param_size = sizeof(BCRYPT_DH_PARAMETER_HEADER) + dh_prime_len + dh_gen_len;
	unsigned char* dh_params = (unsigned char*)calloc(dh_param_size, sizeof(uint8_t));
	BCRYPT_DH_PARAMETER_HEADER* dh_params_struct = (BCRYPT_DH_PARAMETER_HEADER*)dh_params;
	if (!dh_params) {
		printf("error allocating dh_params structure. 0x%x, %d\n", GetLastError(), GetLastError());
		return -1;
	}
	
	// get diffie-hellman bcrypt algorithm provider
	BCRYPT_ALG_HANDLE hDHalg = NULL;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&hDHalg, BCRYPT_DH_ALGORITHM, NULL, 0);
	if (status != 0) {
		printf("Error BCryptOpenAlgorithmProvider 0x%x, %d\n", status, status);
		goto cleanup;
	}

	// create empty key pair
	status = BCryptGenerateKeyPair(hDHalg, &dh_key, (ULONG)(dh_prime_len * 8), 0);
	if (status != 0) {
		printf("Error DH BCryptGenerateKeyPair 0x%x, %d\n", status, status);
		goto cleanup;
	}

	// Fill and set DH parameter structure with prime and generator
	dh_params_struct->cbLength = (ULONG)dh_param_size;
	dh_params_struct->cbKeyLength = (ULONG)dh_prime_len;
	dh_params_struct->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
	memcpy(dh_params + sizeof(BCRYPT_DH_PARAMETER_HEADER), dh_prime, dh_prime_len);
	memcpy(dh_params + sizeof(BCRYPT_DH_PARAMETER_HEADER) + dh_prime_len, dh_gen, dh_gen_len);
	status = BCryptSetProperty(dh_key, BCRYPT_DH_PARAMETERS, dh_params, (ULONG)dh_param_size, 0);
	if (status != 0) {
		printf("Error DH BCryptSetProperty 0x%x, %d\n", status, status);
		goto cleanup;
	}

	// create client pub/priv key pair

	status = BCryptFinalizeKeyPair(dh_key, 0);
	if (status != 0) {
		printf("Error DH BCryptFinalizeKeyPair 0x%x, %d\n", status, status);
		goto cleanup;
	}

	// export client public
	status = BCryptExportKey(dh_key, NULL, BCRYPT_DH_PUBLIC_BLOB, NULL, 0, &pubkey_blob_len, 0);
	if (status != 0) {
		printf("Error BCryptExportKey1 0x%x, %d\n", status, status);
		goto cleanup;
	}

	pubkey_blob = (PUCHAR)calloc(pubkey_blob_len, 1);
	if (pubkey_blob == NULL) {
		printf("Could not allocate public DH key. 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	status = BCryptExportKey(dh_key, NULL, BCRYPT_DH_PUBLIC_BLOB, pubkey_blob, pubkey_blob_len, &pubkey_blob_len, 0);
	if (status != 0) {
		printf("Error BCryptExportKey2 0x%x, %d\n", status, status);
		goto cleanup;
	}

	// pull raw public key from public key blob (removes prime and generator)
	*pubkey_len = pubkey_blob_len - key_blob_len;
	if (*pubkey_len > 0) {
		*pubkey = (char*)calloc(*pubkey_len, sizeof(char));
		if (!(*pubkey)) {
			printf("failure to allocate pubkey memory 0x%x, %d\n", GetLastError(), GetLastError());
			goto cleanup;
		}
		memcpy(*pubkey, pubkey_blob + key_blob_len, *pubkey_len);
	}
	else {
		printf("error pubkey_len not valid length: %d\n", *pubkey_len);
		goto cleanup;
	}

	// export shared secret to use for encryption

	//manually create the server public key blob to import
	server_public_key_blob = (unsigned char*)calloc(server_public_key_blob_size, sizeof(uint8_t));
	if (!server_public_key_blob) {
		printf("failed to allocate space for server public key blob 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}
	public_key_blob_struct = (BCRYPT_DH_KEY_BLOB*)server_public_key_blob;
	public_key_blob_struct->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
	public_key_blob_struct->cbKey = (ULONG)srv_pubkey_len;
	memcpy(server_public_key_blob + sizeof(BCRYPT_DH_KEY_BLOB), dh_prime, dh_prime_len);
	memcpy(server_public_key_blob + sizeof(BCRYPT_DH_KEY_BLOB) + dh_prime_len, dh_gen, dh_gen_len);
	memcpy(server_public_key_blob + sizeof(BCRYPT_DH_KEY_BLOB) + dh_prime_len + dh_gen_len, srv_pubkey, srv_pubkey_len);

	status = BCryptImportKeyPair(hDHalg, NULL, BCRYPT_DH_PUBLIC_BLOB, &hPublickey, server_public_key_blob, server_public_key_blob_size, 0);
	if (status != 0) {
		printf("Error BCryptImportKeyPair 0x%x, %d\n", status, status);
		goto cleanup;
	}

	status = BCryptSecretAgreement(dh_key, hPublickey, &hAgreedSecret, 0);
	if (status != 0) {
		printf("Error BCryptSecretAgreement 0x%x, %d\n", status, status);
		goto cleanup;
	}

	status = BCryptDeriveKey(hAgreedSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, (ULONG*)secret_len, 0);
	if (status != 0) {
		printf("Error BCryptDeriveKey 0x%x, %d\n", status, status);
		goto cleanup;
	}

	*secret = (char*)calloc(*secret_len, sizeof(uint8_t));
	if (!(*secret)) {
		printf("Error allocation 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	status = BCryptDeriveKey(hAgreedSecret, BCRYPT_KDF_RAW_SECRET, NULL, (PUCHAR)*secret, *secret_len, (ULONG*)secret_len, 0);
	if (status != 0) {
		printf("Error BCryptSecretAgreement 0x%x, %d\n", status, status);
		goto cleanup;
	}

	// TODO figure out if secret needs to be switched from little endian byte order!!!!!!!!!!!!!!!!!!!!!!!!!!!

cleanup:
	if (server_public_key_blob)
		free(server_public_key_blob);

	if (pubkey_blob)
		free(pubkey_blob);

	if (hDHalg)
		BCryptCloseAlgorithmProvider(hDHalg, 0);

	if (dh_params)
		free(dh_params);

	return 0;
}