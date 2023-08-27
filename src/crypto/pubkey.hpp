extern "C" {

#ifndef WG_KEY_LEN
#define WG_KEY_LEN 32
#endif

#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)

/*
 * wg_pubkey_base64 is a C++-compatible wrapper for the curve25519 public-key
 * derivation routines used natively in `wg(8)`
 *
 * PRIVKEY: a c-style string containing the base64-encoded private key
 * BASE64:  a c-style string of capacity WG_KEY_LEN_BASE64 containing the
 * encoded public key
 *
 * returns: 0 on success
 *          > 0 when an error occurs (due to improper key formatting)
 */
int wg_pubkey_base64(char const * privkey, char * base64);

}
