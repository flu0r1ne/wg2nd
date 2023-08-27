extern "C" {

#ifndef WG_KEY_LEN
#define WG_KEY_LEN 32
#endif

#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)
#define WG_KEY_LEN_BASE32 (((WG_KEY_LEN + 4) / 5) * 8 + 1)

/*
 * wg_pubkey_base64 is a C++-compatible wrapper for the curve25519 public-key
 * derivation routines used natively in `wg(8)`
 *
 * PRIVKEY: a c-style string containing the base64-encoded private key
 * BASE32:  a c-style string of capacity WG_KEY_LEN_BASE64 containing the
 * encoded public key
 *
 * returns: 0 on success
 *          > 0 when an error occurs (due to improper key formatting)
 */
int wg_pubkey_base32(char const * privkey, char * base32);

int wg_key_convert_base32(char const * base64, char * base32);

}
