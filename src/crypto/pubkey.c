#include "curve25519.h"
#include "encoding.h"

#define WG_KEY_LEN_BASE32 (((WG_KEY_LEN + 4) / 5) * 8 + 1)
#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)

static inline void encode_base32(char dest[static 8], const uint8_t src[static 5]) {
	const uint8_t input[] = {
		  src[0] >> 3,
		((src[0] & 0x07) << 2) | (src[1] >> 6),
		 (src[1] & 0x3F) >> 1,
		((src[1] & 0x01) << 4) | (src[2] >> 4),
		((src[2] & 0x0F) << 1) | (src[3] >> 7),
		 (src[3] & 0x7F) >> 2,
		((src[3] & 0x03) << 3) | (src[4] >> 5),
		  src[4] & 0x1F
	};

	for(unsigned int i = 0; i < 8; i++)
		dest[i] = 'A' + input[i] - (((25 - input[i]) >> 8) & 41);
}

void key_to_base32(char base32[static WG_KEY_LEN_BASE32], const uint8_t key[static WG_KEY_LEN])
{
	unsigned int i;

	for (i = 0; i < WG_KEY_LEN / 5; ++i)
		encode_base32(&base32[i * 8], &key[i * 5]);
	encode_base32(&base32[i * 8], (const uint8_t[]){ key[i * 5 + 0], key[i * 5 + 1], 0, 0, 0 });
	base32[WG_KEY_LEN_BASE32 - 5] = '=';
	base32[WG_KEY_LEN_BASE32 - 4] = '=';
	base32[WG_KEY_LEN_BASE32 - 3] = '=';
	base32[WG_KEY_LEN_BASE32 - 2] = '=';
	base32[WG_KEY_LEN_BASE32 - 1] = '\0';
}

int wg_pubkey_base32(char const * privkey, char * base32) {

	uint8_t key[WG_KEY_LEN] __attribute((aligned(sizeof(uintptr_t))));
	char base64[WG_KEY_LEN_BASE64];

	int i;
	for(i = 0; privkey[i] && i < WG_KEY_LEN_BASE64 - 1; i++)
		base64[i] = privkey[i];

	base64[WG_KEY_LEN_BASE64 - 1] = '\0';

	if(i != WG_KEY_LEN_BASE64 - 1 || privkey[i]) {
		return 1;
	}

	if(!key_from_base64(key, base64)) {
		return 1;
	}

	curve25519_generate_public(key, key);

	key_to_base32(base32, key);

	return 0;
}

int wg_key_convert_base32(char const * base64, char * base32) {
	uint8_t key[WG_KEY_LEN] __attribute((aligned(sizeof(uintptr_t))));

	if(!key_from_base64(key, base64)) {
		return 1;
	}

	key_to_base32(base32, key);

	return 0;
}
