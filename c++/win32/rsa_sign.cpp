NTSTATUS rsa_sign(char* hash, size_t hash_len, char** signed_data, uint32_t* signed_data_len)
{
	NTSTATUS status = -1;
	BCRYPT_ALG_HANDLE hSignAlg = NULL;
	BOOL ret = FALSE;
	BYTE* privKeyBuf = NULL;
	DWORD privKeyBufLen = 0;
	void* keyBlob = NULL;
	DWORD keyBlobLen = 0;
	BCRYPT_KEY_HANDLE hKey = NULL;
	ULONG ret_len = 0;

	PUCHAR output = NULL;
	ULONG outputlen = 0;

	DWORD keyLength = 2048;
	BCRYPT_PKCS1_PADDING_INFO padding_PKCS1 = BCRYPT_PKCS1_PADDING_INFO();

	SECURITY_STATUS sstatus = 0;
	NCRYPT_PROV_HANDLE hProv = NULL;
	NCRYPT_KEY_HANDLE hKKey = NULL;

	if (!signed_data || !signed_data_len) {
		printf("invalid input values to sha512\n");
		return -1;
	}
	
	status = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
	//status = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_RSA_SIGN_ALGORITHM, NULL, 0);
	if (status != 0) {
		printf("Error getting alogorithm provider for rsa signing. 0x%x, %d\n", status, status);
		return -1;
	}

	// check to see how much space is needed for privkey string conversion to binary
	ret = CryptStringToBinaryA(szRsaPrivKey, 0, CRYPT_STRING_BASE64_ANY, NULL, &privKeyBufLen, 0, 0);
	if (ret == FALSE) {
		printf("failure getting space size of privkey conversion. 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	// allocate space for string to binary conversion
	privKeyBuf = (BYTE*)calloc(privKeyBufLen, sizeof(BYTE));
	if (!privKeyBuf) {
		printf("failure to allocate space for privkey conversion. 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	// convert rsa private key (pem format) to binary
	ret = CryptStringToBinaryA(szRsaPrivKey, 0, CRYPT_STRING_BASE64_ANY, privKeyBuf, &privKeyBufLen, 0, 0);
	if (ret == FALSE) {
		printf("failure converting privkey. 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	// get size of rsa private key keyblob
	ret = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, privKeyBuf, privKeyBufLen, 0, NULL, NULL, &keyBlobLen);
	if (ret == FALSE) {
		printf("failure getting size of privkey decode. 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	// allocate space for rsa private key keyblob
	keyBlob = calloc(keyBlobLen, sizeof(BYTE));
	if (!keyBlob) {
		printf("failure to allocate space for privkey keyblob. 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	// create rsa private key keyblob
	ret = CryptDecodeObjectEx(PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, privKeyBuf, privKeyBufLen, 0, NULL, keyBlob, &keyBlobLen);
	if (ret == FALSE) {
		printf("failure creating private key keyblob. 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	// get ncrypt storage provider
	sstatus = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
	if (sstatus != 0) {
		printf("Error NCryptOpenStorageProvide. 0x%x, %d\n", sstatus, sstatus);
		goto cleanup;
	}

	// import rsa legacy private key blob
	sstatus = NCryptImportKey(hProv, NULL, LEGACY_RSAPRIVATE_BLOB, NULL, &hKKey, (PBYTE)keyBlob, keyBlobLen, 0);
	if (sstatus != 0) {
		printf("Error NCryptImportKey. 0x%x, %d\n", sstatus, sstatus);
		goto cleanup;
	}

	// 
	//sstatus = NCryptSetProperty(hKKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)(&keyLength), sizeof(keyLength), NCRYPT_PERSIST_FLAG);
	//if (sstatus != 0) {
	//	printf("Error BCryptSetProperty rsa signing private key. 0x%x, %d\n", sstatus, sstatus);
	//	goto cleanup;
	//}

	// get size of rsa signed buf
	//sstatus = NCryptSignHash(hKKey, &padding_PKCS1, (PUCHAR)hash, hash_len, NULL, 0, &ret_len, BCRYPT_PAD_PKCS1);
	sstatus = NCryptSignHash(hKKey, NULL, (PUCHAR)hash, hash_len, NULL, 0, &ret_len, 0);
	if (sstatus != 0) {
		printf("Error getting signed output size. 0x%x, %d\n", sstatus, sstatus);
		goto cleanup;
	}

	// allocate space for rsa signed buf
	(*signed_data_len) = ret_len;
	(*signed_data) = (char*)calloc((*signed_data_len), sizeof(BYTE));
	if (!(*signed_data)) {
		printf("failure to allocate space for signed buffer. 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	// sign hash with rsa key
	//sstatus = NCryptSignHash(hKKey, &padding_PKCS1, (PUCHAR)hash, hash_len, (PBYTE)(*signed_data), (*signed_data_len), &ret_len, BCRYPT_PAD_PKCS1);
	sstatus = NCryptSignHash(hKKey, NULL, (PUCHAR)hash, hash_len, (PBYTE)(*signed_data), (*signed_data_len), &ret_len, 0);
	if (sstatus != 0) {
		printf("Error signing hash. 0x%x, %d\n", sstatus, sstatus);
		goto cleanup;
	}

cleanup:
	if (hKey)
		BCryptDestroyKey(hKey);

	if (keyBlob)
		free(keyBlob);

	if (privKeyBuf)
		free(privKeyBuf);

	if (hSignAlg)
		BCryptCloseAlgorithmProvider(hSignAlg, 0);

	return status;
}