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
  u8 key[crypto_box_public_key_bytes];
} asn_user_id_t;

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

always_inline uword
asn_pdu_n_content_bytes_for_blob (asn_pdu_blob_t * b, u32 n_bytes_in_pdu)
{
  ASSERT (n_bytes_in_pdu >= sizeof (b[0]) + b->n_name_bytes);
  return n_bytes_in_pdu - sizeof (b[0]) - b->n_name_bytes;
}

typedef struct {
  char * name;

  /* Index for this type.  Set when registering. */
  u32 index;

  /* Size and offset of asn_user_t in super type. */
  u32 user_type_n_bytes;
  u32 user_type_offset_of_asn_user;

  /* Pool of users with this type. */
  void * user_pool;
} asn_user_type_t;

asn_user_type_t ** asn_user_type_pool;

always_inline uword
asn_register_user_type (asn_user_type_t * t)
{
  uword ti = pool_set_elt (asn_user_type_pool, t);
  t->index = ti;
  return ti;
}  

/* A reference to a user type and pool index. */
typedef struct {
  u32 type_index;
  u32 user_index;
} asn_user_ref_t;

always_inline void
asn_user_ref_from_uword (asn_user_ref_t * r, uword w)
{
  r->user_index = w >> 6;
  r->type_index = w & pow2_mask (6);
}

always_inline uword
asn_user_ref_as_uword (asn_user_ref_t * r)
{
  uword w = (r->user_index << 6) | r->type_index;
  if (CLIB_DEBUG > 0)
    {
      asn_user_ref_t t;
      asn_user_ref_from_uword (&t, w);
      ASSERT (t.user_index == r->user_index);
      ASSERT (t.type_index == r->type_index);
    }
  return w;
}

struct asn_user_t;

always_inline struct asn_user_t *
asn_user_by_ref (asn_user_ref_t * r)
{
  asn_user_type_t * ut = pool_elt (asn_user_type_pool, r->type_index);
  if (pool_is_free_index (ut->user_pool, r->user_index))
    return 0;
  else
    return ut->user_pool + r->user_index*ut->user_type_n_bytes + ut->user_type_offset_of_asn_user;
}

always_inline struct asn_user_t *
asn_user_by_ref_as_uword (uword k)
{
  asn_user_ref_t r;
  asn_user_ref_from_uword (&r, k);
  return asn_user_by_ref (&r);
}

always_inline void *
asn_user_pool_for_user_ref (asn_user_ref_t * r)
{
  asn_user_type_t * ut = pool_elt (asn_user_type_pool, r->type_index);
  return ut->user_pool;
}

always_inline void *
asn_user_pool_for_user_type (u32 type_index)
{
  asn_user_type_t * ut = pool_elt (asn_user_type_pool, type_index);
  return ut->user_pool;
}

typedef struct {
  u8 user[8];
  union {
    struct {
      i32 longitude_mul_1e6;
      i32 latitude_mul_1e6;
    };
    struct {
      /* 0x7X where X is ETA. */
      u8 place_and_eta;

      /* First 7 bytes of place/event public key. */
      u8 place[7];
    };
  };
} asn_user_mark_response_t;

always_inline uword
asn_user_mark_response_is_place (asn_user_mark_response_t * r)
{ return (r->place_and_eta & 0xf0) == 0x70; }

always_inline uword
asn_user_mark_response_place_eta (asn_user_mark_response_t * r)
{
  ASSERT (asn_user_mark_response_is_place (r));
  return r->place_and_eta & 0xf;
}

typedef struct asn_user_t 
{
  /* Index into user pool. */
  u32 index;

  /* True when private key is valid for this user.
     For most users we don't know private keys. */
  u32 private_key_is_valid : 1;

  /* Indexed by is_place. */
  u32 current_marks_are_valid : 2;

  u32 user_type_index : 29;

  asn_crypto_keys_t crypto_keys;

  /* Indexed by is_place. */
  asn_user_mark_response_t current_marks[2];

  /* Nonce and shared secret for communication between this user and other users.
     Indexed by known user pool index. */
  asn_crypto_state_t * crypto_state_by_user_index;

  /* Bitmap to indicate whether above array indices are valid. */
  uword * crypto_state_by_user_index_is_valid_bitmap;
} asn_user_t;

always_inline asn_user_t *
asn_user_alloc_with_type (asn_user_type_t * ut)
{
  asn_user_t * au;
  void * u;
  uword i;
  ut->user_pool = pool_get_free_index (ut->user_pool, ut->user_type_n_bytes, &i);
  u = ut->user_pool + i * ut->user_type_n_bytes;
  memset (u, 0, ut->user_type_n_bytes);
  au = u + ut->user_type_offset_of_asn_user;
  au->user_type_index = ut->index;
  au->index = i;
  return au;
}

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

  u32 client_socket_index;

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

typedef clib_error_t * (asn_blob_handler_function_t) (struct asn_main_t * am, struct asn_socket_t * as, asn_pdu_blob_t * blob, u32 n_bytes_in_pdu);

typedef struct {
  asn_blob_handler_function_t * handler_function;
  u8 * name;
} asn_blob_handler_t;

typedef enum {
#define foreach_asn_socket_type _ (websocket) _ (tcp)
#define _(f) ASN_SOCKET_TYPE_##f,
  foreach_asn_socket_type
#undef _
  ASN_N_SOCKET_TYPE,
} asn_socket_type_t;

typedef struct {
  /* Index in pool. */
  u32 socket_index;

  asn_socket_type_t socket_type;

  struct {
    f64 open, first_close, next_connect_attempt, backoff;
  } timestamps;

  u8 * socket_config;
} asn_client_socket_t;

always_inline void
asn_client_socket_free (asn_client_socket_t * s)
{ vec_free (s->socket_config); }

typedef struct asn_main_t {
  websocket_main_t websocket_main;

  unix_file_poller_t unix_file_poller;
  
  /* Server listen config strings of the form IP[:PORT] */
  u8 * server_config;

  asn_crypto_keys_t server_keys;
  u8 server_nonce[crypto_box_nonce_bytes];

  asn_client_socket_t * client_sockets;

  u32 verbose;

  /* Index and user type of self user. */
  asn_user_ref_t self_user_ref;

  uword * user_ref_by_public_encrypt_key[ASN_N_RX_TX];

  u8 * blob_name_vector_for_reuse;

  asn_blob_handler_t * blob_handlers;

  uword * blob_handler_index_by_name;
} asn_main_t;

always_inline asn_socket_t *
asn_socket_at_index (asn_main_t * am, u32 i)
{
  websocket_socket_t * ws = websocket_at_index (&am->websocket_main, i);
  return CONTAINER_OF (ws, asn_socket_t, websocket_socket);
}

clib_error_t * asn_main_init (asn_main_t * am, u32 user_socket_n_bytes, u32 user_socket_offset_of_asn_socket);
clib_error_t * asn_add_connection (asn_main_t * am, u8 * socket_config, u32 client_socket_index);
clib_error_t * asn_add_listener (asn_main_t * am, u8 * socket_config, int want_random_keys);

always_inline uword
asn_is_user_for_ref (asn_user_t * au, asn_user_ref_t * r)
{ return r->user_index == au->index && r->type_index == au->user_type_index; }

always_inline asn_user_t *
asn_user_with_encrypt_key (asn_main_t * am, asn_rx_or_tx_t rt, u8 * encrypt_key)
{
  uword * p;

  if (am->user_ref_by_public_encrypt_key[rt]
      && (p = hash_get_mem (am->user_ref_by_public_encrypt_key[rt], encrypt_key)))
    return asn_user_by_ref_as_uword (p[0]);
  else
    return 0;
}

asn_user_t *
asn_new_user_with_type (asn_main_t * am,
			asn_rx_or_tx_t rt,
			u32 user_type_index,
			asn_crypto_public_keys_t * with_public_keys,
			asn_crypto_private_keys_t * with_private_keys);

asn_user_t *
asn_update_peer_user (asn_main_t * am, asn_rx_or_tx_t rt, u32 user_type_index, u8 * encrypt_key, u8 * auth_key);

clib_error_t * asn_exec_with_ack_handler (asn_socket_t * as, asn_exec_ack_handler_t * ack_handler, char * fmt, ...);
clib_error_t * asn_exec (asn_socket_t * as, asn_exec_ack_handler_function_t * function, char * fmt, ...);

clib_error_t * asn_login_for_self_user (asn_main_t * am, asn_socket_t * as);

void asn_set_blob_handler_for_name (asn_main_t * am, asn_blob_handler_function_t * handler, char * fmt, ...);
clib_error_t * asn_poll_for_input (asn_main_t * am);

clib_error_t * asn_mark_position (asn_socket_t * as, f64 longitude, f64 latitude);

format_function_t format_asn_user_type, format_asn_user_mark_response;

#endif /* included_asn_h */
