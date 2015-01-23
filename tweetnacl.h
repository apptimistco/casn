#ifndef included_tweetnacl_h
#define included_tweetnacl_h

void crypto_random_bytes(u8 *,u64);
int crypto_box_keypair (u8 * public, u8 * private, int want_random);

#define crypto_box_shared_secret_bytes 32
int crypto_box_beforenm (u8 * shared_secret, const u8 * peer_public, const u8 * self_private);

#define crypto_box_reserved_pad_bytes 32
#define crypto_box_reserved_pad_authentication_offset 16
#define crypto_box_nonce_bytes 24

/* first 32 bytes of clear & cipher are reserved. */
int crypto_box_afternm (u8 * cipher_text,
                        const u8 * clear_text, u64 n_bytes,
                        const u8 * nonce,
                        const u8 * secret_key);

int crypto_box_open_afternm (u8 * clear_text,
                             const u8 * cipher_text,
                             u64 n_bytes,
                             const u8 * nonce,
                             const u8 * secret_key);

#define crypto_box_public_key_bytes 32
#define crypto_box_private_key_bytes 32
#define crypto_box_authentication_bytes 16 /* poly1305 output */
#define crypto_box_block_size 64           /* salsa20 block size */

/* ed25519 */
#define crypto_sign_public_key_bytes 32
#define crypto_sign_private_key_bytes 64
#define crypto_sign_signature_bytes 64

int crypto_sign_keypair (u8 * public, u8 * private, int want_random);

int crypto_sign (u8 * signed_message, u64 * n_signed_message_bytes,
                 const u8 * message, u64 n_message_bytes,
                 const u8 * private_key);
int crypto_sign_open (u8 * message, u64 * n_message_bytes,
                      const u8 * signed_message,
                      u64 n_signed_message_bytes,
                      const u8 * public_key);

#endif /* included_tweetnacl_h */
