NTSTATUS sha512(unsigned char* input, size_t input_len, char** output, size_t* output_len)
{
	NTSTATUS status = -1;
	BCRYPT_ALG_HANDLE hSHA512alg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	ULONG result = 0;
	ULONG retData = 0;
	ULONG hashObjectLen = 0;
	PUCHAR hashObject = NULL;
	//ULONG hashLen = 0;
	//PUCHAR hash = NULL;

	if (!output || !output_len) {
		printf("invalid input values to sha512\n");
		return -1;
	}

	// open an algorithm handle
	status = BCryptOpenAlgorithmProvider(&hSHA512alg, BCRYPT_SHA512_ALGORITHM, NULL, 0);
	if (status != 0) {
		printf("Error getting alogorithm provider for sha512. 0x%x, %d\n", status, status);
		return -1;
	}

	// calculate the size of the buffer to hold the hash object
	status = BCryptGetProperty(hSHA512alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectLen, sizeof(ULONG), &retData, 0);
	if (status != 0) {
		printf("Error getting sha512 object length. 0x%x, %d\n", status, status);
		goto cleanup;
	}

	hashObject = (PUCHAR)calloc(hashObjectLen, sizeof(UCHAR));
	if (!hashObject) {
		printf("Error allocating space for sha512 object 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	// calculate the length of the hash
	status = BCryptGetProperty(hSHA512alg, BCRYPT_HASH_LENGTH, (PUCHAR)output_len, sizeof(ULONG), &retData, 0);
	if (status != 0) {
		printf("Error getting sha512 hash length. 0x%x, %d\n", status, status);
		goto cleanup;
	}

	// allocate the hash buffer on the heap
	(*output) = (char*)calloc(*output_len, sizeof(UCHAR));
	if (!(*output)) {
		printf("Error allocating space for sha512 hash 0x%x, %d\n", GetLastError(), GetLastError());
		goto cleanup;
	}

	// create hash
	status = BCryptCreateHash(hSHA512alg, &hHash, hashObject, hashObjectLen, NULL, 0, 0);
	if (status != 0) {
		printf("Error creating sha512 hash empty object. 0x%x, %d\n", status, status);
		goto cleanup;
	}

	// hash some data
	status = BCryptHashData(hHash, (PUCHAR)input, input_len, 0);
	if (status != 0) {
		printf("Error sha512 hasing of input. 0x%x, %d\n", status, status);
		goto cleanup;
	}

	// finish the hash
	status = BCryptFinishHash(hHash, (PUCHAR)*output, *output_len, 0);
	if (status != 0) {
		printf("Error finalizing sha512 hash. 0x%x, %d\n", status, status);
		goto cleanup;
	}

cleanup:
	if (hHash)
		BCryptDestroyHash(hHash);

	if (hashObject)
		free(hashObject);

	if (hSHA512alg)
		BCryptCloseAlgorithmProvider(hSHA512alg, 0);

	return status;
}