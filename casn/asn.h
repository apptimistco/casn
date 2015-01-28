#ifndef included_asn_h
#define included_asn_h

#include <uclib/uclib.h>
#include <casn/tweetnacl.h>

typedef struct {
  u8 auth_key[crypto_sign_private_key_bytes];
  u8 encrypt_key[crypto_box_private_key_bytes];
} asn_crypto_private_keys_t;

typedef struct {
  u8 auth_key[crypto_sign_public_key_bytes];
  u8 encrypt_key[crypto_box_public_key_bytes];

  /* Signature of public encrypt key signed by auth key.
     Known after login request. */
  u8 self_signed_encrypt_key[crypto_sign_signature_bytes];
} asn_crypto_public_keys_t;

typedef struct {
  asn_crypto_private_keys_t private;
  asn_crypto_public_keys_t public;
} asn_crypto_keys_t;

typedef struct {
  u8 private[crypto_box_private_key_bytes];
  u8 public[crypto_box_public_key_bytes];
} asn_crypto_ephemeral_keys_t;

/* Receive or transmit. */
typedef enum {
  ASN_RX,
  ASN_TX,
  ASN_N_RX_TX,
} asn_rx_or_tx_t;

typedef struct {
  u8 shared_secret[crypto_box_shared_secret_bytes];
  u8 nonce[ASN_N_RX_TX][crypto_box_nonce_bytes];
} asn_crypto_state_t;

#define foreach_asn_pdu_id                      \
  _ (ack, 1)					\
  _ (exec, 2)					\
  _ (login, 3)					\
  _ (pause, 4)					\
  _ (quit, 5)					\
  _ (redirect, 6)				\
  _ (resume, 7)					\
  _ (blob, 8)					\
  _ (index, 9)

typedef enum {
#define _(f,n) ASN_PDU_##f = n,
  foreach_asn_pdu_id
#undef _
  ASN_N_PDU,
} asn_pdu_id_t;

/* PDUs are broken up into frames of at most 4094 bytes preceeded by a u16 control word
   followed by 16 bytes of poly1305 authentication. */
typedef CLIB_PACKED (struct {
  /* More flag indicates more segments follow else end of PDU. */
#define ASN_PDU_FRAME_LOG2_MORE_FLAG (15)
#define ASN_PDU_FRAME_MORE_FLAG (1 << ASN_PDU_FRAME_LOG2_MORE_FLAG)

  union {
    /* Number of bytes that following (including authentication). */
    u16 n_bytes_that_follow_and_more_flag_network_byte_order;
    u16 n_user_data_bytes;
  };

  /* 16 byte poly1305 authenticator for user data. */
  u8 user_data_authentication[crypto_box_authentication_bytes];

  /* Up to 4096 - 2 - 16 bytes of user data follow. */
  u8 user_data[4096 - sizeof (u16) - crypto_box_authentication_bytes];
}) asn_pdu_frame_t;

typedef CLIB_PACKED (struct {
  /* ASN version: set to 0. */
  u8 version;

  /* PDU id. */
  asn_pdu_id_t id : 8;

  /* Identifies request. */
  union {
    u8 request_id[8];

    struct {
      asn_pdu_id_t id : 8;

      u8 is_self_user_login;

      u8 unused[2];

      u32 ack_handler_index;
    } casn_request_id;

    u8 blob_magic[8];           /* "asnmagic\0" for blobs. */
  };

  /* More header plus data follows. */
  u8 data[0];
}) asn_pdu_header_t;

#define foreach_asn_ack_pdu_status              \
  _ (success)                                   \
  _ (access_denied)                             \
  _ (failure)                                   \
  _ (illegal_format)                            \
  _ (incompatible)                              \
  _ (redirect)                                  \
  _ (short)                                     \
  _ (unexpected)                                \
  _ (unknown)                                   \
  _ (unsupported)

typedef enum {
#define _(f) ASN_ACK_PDU_STATUS_##f,
  foreach_asn_ack_pdu_status
#undef _
  ASN_N_ACK_PDU_STATUS,
} asn_ack_pdu_status_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* ASN_ACK_PDU_STATUS_* */
  u8 status;

  /* Data follows. */
  u8 data[0];
}) asn_pdu_ack_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* Public encryption key of user. */
  u8 key[32];

  /* ed25519 signature of above key signed by user's private authentication key. */
  u8 signature[64];
}) asn_pdu_login_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* Random data to make SHA sum of blob unique. */
  u8 random[32];

  /* Owner or destination of message. */
  u8 owner[32];

  /* Author or sender of message. */
  u8 author[32];

  u64 time_stamp_in_nsec_from_1970;

  /* Name length and contents follow (zero length name for "messages"). */
  u8 n_name_bytes;
  u8 name[0];

  /* Contents of blob follows name. */
  u8 contents[0];
}) asn_pdu_blob_t;

always_inline void *
asn_pdu_contents_for_blob (asn_pdu_blob_t * b)
{
  /* Content is after name. */
  return b->name + b->n_name_bytes;
}

#define foreach_asn_user_type \
  _ (unspecified) _ (actual) _ (forum) _ (bridge) _ (place)

typedef enum {
#define _(f) ASN_USER_TYPE_##f,
  foreach_asn_user_type
#undef _
  ASN_N_USER_TYPE,
} asn_user_type_t;

typedef struct {
  /* ASN_USER_TYPE_* */
  asn_user_type_t user_type;

  /* Index into user pool. */
  u32 index;

  /* True when private key is valid for this user.
     For most users we don't know private keys. */
  u32 private_key_is_valid : 1;

  asn_crypto_keys_t crypto_keys;

  union {
    struct {
      /* Nonce and shared secret for communication between this user and other users.
         Indexed by known user pool index. */
      asn_crypto_state_t * crypto_state_by_user_index;

      /* Bitmap to indicate whether above array indices are valid. */
      uword * crypto_state_by_user_index_is_valid_bitmap;
    } tx;

    struct {
      uword * socket_indices_logged_in_as_this_user;
    } rx;
  };
} asn_user_t;

#define foreach_asn_session_state               \
  _ (opened)					\
  _ (provisional)                               \
  _ (established)                               \
  _ (suspended)                                 \
  _ (quiting)                                   \
  _ (close)

typedef enum {
#define _(f) ASN_SESSION_STATE_##f,
  foreach_asn_session_state
#undef _
  ASN_N_SESSION_STATE,
} asn_session_state_t;

typedef struct {
  /* Full frames preceeding last frame. */
  asn_pdu_frame_t * full_frames;

  u32 n_user_bytes_in_last_frame;

  asn_pdu_frame_t last_frame;

  /* Vector of data which spans frames. */
  u8 * overflow_data;
} asn_pdu_t;

always_inline void
asn_pdu_free (asn_pdu_t * p) 
{
  vec_free (p->full_frames);
  vec_free (p->overflow_data);
}

struct asn_main_t;
struct asn_socket_t;
struct asn_exec_ack_handler_t;

typedef clib_error_t * (asn_exec_ack_handler_function_t) (struct asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data);

typedef struct asn_exec_ack_handler_t {
  struct asn_main_t * asn_main;
  struct asn_socket_t * asn_socket;
  u32 container_offset_of_object;
  asn_exec_ack_handler_function_t * function;
} asn_exec_ack_handler_t;

always_inline void *
asn_exec_ack_handler_create_with_function_in_container (asn_exec_ack_handler_function_t * f, uword sizeof_object, uword object_offset_of_ack_handler)
{
  asn_exec_ack_handler_t * ah = clib_mem_alloc_in_container (sizeof (ah[0]), sizeof_object, object_offset_of_ack_handler);
  ah->function = f;
  ah->container_offset_of_object = object_offset_of_ack_handler;
  return (void *) ah - object_offset_of_ack_handler;
}

always_inline asn_exec_ack_handler_t *
asn_exec_ack_handler_create_with_function (asn_exec_ack_handler_function_t * f)
{ return asn_exec_ack_handler_create_with_function_in_container (f, sizeof (asn_exec_ack_handler_t), /* object_offset_of_ack_handler */ 0); }

typedef struct asn_socket_t {
  websocket_socket_t websocket_socket;

  /* PDUs to be combined into a single websocket data frame. */
  asn_pdu_t * tx_pdus;

  /* Currently received PDU we're working on. */
  u8 * rx_pdu;

  /* Hash table which has entries for all user indices logged in on this socket. */
  uword * users_logged_in_this_socket;

  asn_crypto_ephemeral_keys_t ephemeral_keys;

  /* Nonce and shared secret. */
  asn_crypto_state_t ephemeral_crypto_state;

  asn_exec_ack_handler_t ** exec_ack_handler_pool;

  asn_session_state_t session_state;

  u32 unknown_self_user_newuser_in_progress : 1;
  u32 self_user_login_in_progress : 1;
} asn_socket_t;

always_inline void
asn_socket_free (asn_socket_t * as)
{
  asn_pdu_t * p;
  vec_free (as->rx_pdu);
  vec_foreach (p, as->tx_pdus)
    asn_pdu_free (p);
  vec_free (as->tx_pdus);
  hash_free (as->users_logged_in_this_socket);
}

typedef struct {
  asn_user_t * user_pool;

  uword * user_by_public_encrypt_key;
} asn_known_users_t;

typedef clib_error_t * (asn_blob_handler_function_t) (struct asn_main_t * am, struct asn_socket_t * as, asn_pdu_blob_t * blob, u32 n_bytes_in_pdu);

typedef struct {
  asn_blob_handler_function_t * handler_function;
  u8 * name;
} asn_blob_handler_t;

typedef struct asn_main_t {
  websocket_main_t websocket_main;

  unix_file_poller_t unix_file_poller;
  
  /* Server listen config strings of the form IP[:PORT] */
  u8 * server_config;

  asn_crypto_keys_t server_keys;
  u8 server_nonce[crypto_box_nonce_bytes];

  u8 * client_config;

  u32 verbose;

  /* Index of self user (normally 0). */
  u32 self_user_index;

  asn_known_users_t known_users[ASN_N_RX_TX];

  u8 * blob_name_vector_for_reuse;

  asn_blob_handler_t * blob_handlers;

  uword * blob_handler_index_by_name;
} asn_main_t;

clib_error_t * asn_main_init (asn_main_t * am, u32 user_socket_n_bytes, u32 user_socket_offset_of_asn_socket);
clib_error_t * asn_add_connection (asn_main_t * am, u8 * socket_config);
clib_error_t * asn_add_listener (asn_main_t * am, u8 * socket_config, int want_random_keys);

always_inline asn_user_t *
asn_user_with_encrypt_key (asn_main_t * am, asn_rx_or_tx_t rt, u8 * encrypt_key)
{
  asn_known_users_t * ku = &am->known_users[rt];
  uword * p;

  if (pool_elts (ku->user_pool) > 0
      && (p = hash_get_mem (ku->user_by_public_encrypt_key, encrypt_key)))
    return pool_elt_at_index (ku->user_pool, p[0]);
  else
    return 0;
}

asn_user_t *
asn_new_user_with_type (asn_main_t * am,
			asn_rx_or_tx_t rt,
			asn_user_type_t with_user_type,
			asn_crypto_public_keys_t * with_public_keys,
			asn_crypto_private_keys_t * with_private_keys);

clib_error_t * asn_exec_with_ack_handler (asn_socket_t * as, asn_exec_ack_handler_t * ack_handler, char * fmt, ...);
clib_error_t * asn_exec (asn_socket_t * as, asn_exec_ack_handler_function_t * function, char * fmt, ...);

clib_error_t * asn_login_for_self_user (asn_main_t * am, asn_socket_t * as);

void asn_set_blob_handler_for_name (asn_main_t * am, asn_blob_handler_function_t * handler, char * fmt, ...);

format_function_t format_asn_user_type;

#endif /* included_asn_h */
