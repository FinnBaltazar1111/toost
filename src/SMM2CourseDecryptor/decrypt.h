#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>


#include "aes.h"

#define STATE_SIZE 4
#define NUM_ROUNDS 4

#define SWAP(x) ((x >> 24) & 0xff | (x >> 8) & 0xff00 | (x << 8) & 0xff0000 | (x << 24) & 0xff000000)

namespace LevelDecryptor {
	void rand_init(uint32_t* rand_state, uint32_t in1, uint32_t in2, uint32_t in3, uint32_t in4);

	uint32_t rand_gen(uint32_t* rand_state);

	void gen_key(uint32_t* key_table, uint32_t* out_key, uint32_t* rand_state);

	void aes_cmac(const uint8_t* key, const uint8_t* data, size_t length, uint8_t* mac);

	bool decrypt(std::string& input, std::string& output);

	bool encrypt(std::string& input, std::string& output);
};