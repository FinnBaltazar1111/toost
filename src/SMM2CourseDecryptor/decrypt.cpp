#include "decrypt.h"
#include "keys.h"

#include <random>
#include <zlib.h>

void LevelDecryptor::rand_init(uint32_t* rand_state, uint32_t in1, uint32_t in2, uint32_t in3, uint32_t in4) {
	int cond = in1 | in2 | in3 | in4;

	rand_state[0] = cond ? in1 : 1;
	rand_state[1] = cond ? in2 : 0x6C078967;
	rand_state[2] = cond ? in3 : 0x714ACB41;
	rand_state[3] = cond ? in4 : 0x48077044;
}

uint32_t LevelDecryptor::rand_gen(uint32_t* rand_state) {
	uint32_t n    = rand_state[0] ^ rand_state[0] << 11;
	rand_state[0] = rand_state[1];
	n ^= n >> 8 ^ rand_state[3] ^ rand_state[3] >> 19;
	rand_state[1] = rand_state[2];
	rand_state[2] = rand_state[3];
	rand_state[3] = n;
	return n;
}

void LevelDecryptor::gen_key(uint32_t* key_table, uint32_t* out_key, uint32_t* rand_state) {
	out_key[0] = 0;

	for(int i = 0; i < STATE_SIZE; i++) {
		for(int j = 0; j < NUM_ROUNDS; j++) {
			out_key[i] <<= 8;
			out_key[i] |= (key_table[rand_gen(rand_state) >> 26] >> ((rand_gen(rand_state) >> 27) & 24)) & 0xFF;
		}
	}
}

static void xor_block(uint8_t* dst, const uint8_t* src) {
	for(int i = 0; i < 16; i++) {
		dst[i] ^= src[i];
	}
}

static void shift_left_block(const uint8_t* input, uint8_t* output) {
	uint8_t carry = 0;
	for(int i = 15; i >= 0; i--) {
		output[i] = (input[i] << 1) | carry;
		carry     = (input[i] >> 7) & 1;
	}
}

void LevelDecryptor::aes_cmac(const uint8_t* key, const uint8_t* data, size_t length, uint8_t* mac) {
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);

	// Generate subkeys K1, K2
	uint8_t L[16] = { 0 };
	AES_ECB_encrypt(&ctx, L);

	uint8_t K1[16];
	shift_left_block(L, K1);
	if(L[0] & 0x80) {
		K1[15] ^= 0x87;
	}

	uint8_t K2[16];
	shift_left_block(K1, K2);
	if(K1[0] & 0x80) {
		K2[15] ^= 0x87;
	}

	// Process blocks
	size_t n = (length + 15) / 16;
	bool complete;
	if(n == 0) {
		n        = 1;
		complete = false;
	} else {
		complete = (length % 16 == 0);
	}

	uint8_t X[16] = { 0 };

	for(size_t i = 0; i < n - 1; i++) {
		xor_block(X, data + i * 16);
		// Re-init ctx each time since ECB encrypt modifies internal state
		AES_init_ctx(&ctx, key);
		AES_ECB_encrypt(&ctx, X);
	}

	// Last block
	uint8_t last[16] = { 0 };
	size_t lastBlockStart = (n - 1) * 16;
	size_t remaining      = length - lastBlockStart;

	if(complete) {
		memcpy(last, data + lastBlockStart, 16);
		xor_block(last, K1);
	} else {
		if(remaining > 0) {
			memcpy(last, data + lastBlockStart, remaining);
		}
		last[remaining] = 0x80;
		xor_block(last, K2);
	}

	xor_block(X, last);
	AES_init_ctx(&ctx, key);
	AES_ECB_encrypt(&ctx, X);
	memcpy(mac, X, 16);
}

bool LevelDecryptor::encrypt(std::string& input, std::string& output) {
	if(input.size() != 0x5BFC0) {
		return false;
	}

	output.resize(0x5C000);
	memset(output.data(), 0, 0x5C000);

	// Generate random IV and state seed
	std::random_device rd;
	std::mt19937 rng(rd());
	std::uniform_int_distribution<uint32_t> dist;

	uint8_t iv[16];
	uint32_t state_seed[4];
	for(int i = 0; i < 4; i++) {
		uint32_t r     = dist(rng);
		iv[i * 4]      = r & 0xFF;
		iv[i * 4 + 1]  = (r >> 8) & 0xFF;
		iv[i * 4 + 2]  = (r >> 16) & 0xFF;
		iv[i * 4 + 3]  = (r >> 24) & 0xFF;
		state_seed[i]  = dist(rng);
	}

	// Derive AES encryption key
	uint32_t rand_state[STATE_SIZE];
	uint32_t key_state[STATE_SIZE];
	rand_init(rand_state, state_seed[0], state_seed[1], state_seed[2], state_seed[3]);
	gen_key(course_key_table, key_state, rand_state);

	// Derive CMAC key (continue PRNG stream)
	uint32_t cmac_key_state[STATE_SIZE];
	gen_key(course_key_table, cmac_key_state, rand_state);

	// Compute CRC32 of plaintext
	uint32_t crc = crc32(0L, (const Bytef*)input.data(), input.size());

	// Compute AES-CMAC of plaintext
	uint8_t cmac[16];
	aes_cmac((uint8_t*)cmac_key_state, (const uint8_t*)input.data(), input.size(), cmac);

	// Build the 16-byte header
	uint8_t* hdr       = (uint8_t*)output.data();
	uint32_t index_val = 1;
	uint16_t file_type = 0x10;
	uint16_t flags     = 0;
	memcpy(hdr + 0, &index_val, 4);
	memcpy(hdr + 4, &file_type, 2);
	memcpy(hdr + 6, &flags, 2);
	memcpy(hdr + 8, &crc, 4);
	hdr[12] = 'S';
	hdr[13] = 'C';
	hdr[14] = 'D';
	hdr[15] = 'L';

	// Copy plaintext and encrypt it
	memcpy(output.data() + 0x10, input.data(), 0x5BFC0);

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, (uint8_t*)key_state, iv);
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)output.data() + 0x10, 0x5BFC0);

	// Write crypto config at the end
	uint8_t* end = (uint8_t*)output.data() + 0x5BFD0;
	memcpy(end, iv, 16);                  // IV at +0x00
	memcpy(end + 0x10, state_seed, 16);   // State seed at +0x10
	memcpy(end + 0x20, cmac, 16);         // CMAC at +0x20

	return true;
}

bool LevelDecryptor::decrypt(std::string& input, std::string& output) {
	std::size_t sz = input.size();

	struct AES_ctx ctx;

	uint32_t rand_state[STATE_SIZE];
	uint32_t key_state[STATE_SIZE];

	if(sz == 0x5C000) {
		uint8_t* end = (uint8_t*)input.data() + 0x5BFD0;

		rand_init(
			rand_state, *(uint32_t*)&end[0x10], *(uint32_t*)&end[0x14], *(uint32_t*)&end[0x18], *(uint32_t*)&end[0x1C]);
		gen_key(course_key_table, key_state, rand_state);

		AES_init_ctx_iv(&ctx, (uint8_t*)key_state, end);
		AES_CBC_decrypt_buffer(&ctx, (uint8_t*)input.data() + 0x10, 0x5BFC0);

		output.resize(0x5BFC0);
		memcpy(output.data(), input.data() + 0x10, 0x5BFC0);
		return true;
	} else {
		return false;
	}
}