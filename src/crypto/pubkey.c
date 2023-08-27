#include "curve25519.h"
#include "encoding.h"

int wg_pubkey_base64(char const * privkey, char * base64) {

	uint8_t key[WG_KEY_LEN] __attribute((aligned(sizeof(uintptr_t))));

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

	key_to_base64(base64, key);

	return 0;
}
