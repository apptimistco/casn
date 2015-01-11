#include <uclib/uclib.h>

#ifndef included_asn_h
#define included_asn_h

#include "tweetnacl.h"

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

/* Everything ending with _request is acknowledged with an ACK PDU. */
#define foreach_asn_pdu_id              \
  _ (unused)                            \
  _ (ack)                               \
  _ (exec)                              \
  _ (login)                             \
  _ (pause)                             \
  _ (quit)                              \
  _ (redirect)                          \
  _ (resume)                            \
  _ (blob)

typedef enum {
#define _(f) ASN_PDU_##f,
  foreach_asn_pdu_id
#undef _
  ASN_N_PDU,
} asn_pdu_id_t;

typedef CLIB_PACKED (struct {
  /* More flag indicates more segments follow else end of PDU. */
#define ASN_PDU_SEGMENT_HEADER_LOG2_MORE_FLAG (15)
#define ASN_PDU_SEGMENT_HEADER_MORE_FLAG (1 << ASN_PDU_SEGMENT_HEADER_LOG2_MORE_FLAG)
  u16 n_bytes_in_segment_and_more_flag;

  /* Up to 4094 bytes of data follow. */
  u8 data[0];
}) asn_pdu_segment_header_t;

typedef CLIB_PACKED (struct {
  asn_pdu_segment_header_t header;
  u8 data[4096 - sizeof (asn_pdu_segment_header_t)];
}) asn_pdu_full_segment_t;

#define ASN_PDU_MAX_N_BYTES (4096 - sizeof (asn_pdu_segment_header_t))

typedef CLIB_PACKED (struct {
  /* ASN version: set to 0. */
  u8 version;

  /* PDU id. */
  u8 id;

  /* Identifies request. */
  union {
    u8 request_id[8];
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

#define foreach_asn_user_type \
  _ (actual) _ (forum) _ (bridge)

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

  asn_crypto_keys_t keys;

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

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* Public encryption key of user. */
  u8 key[32];

  /* ed25519 signature of above key signed by user's private authentication key. */
  u8 signature[64];
}) asn_pdu_session_login_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* Null terminated strings follow. */
  u8 data[0];
}) asn_pdu_exec_t;

#endif /* included_asn_h */

u8 * format_asn_pdu_id (u8 * s, va_list * va)
{
  asn_pdu_id_t id = va_arg (*va, asn_pdu_id_t);
  char * t;
  switch (id)
    {
#define _(f) case ASN_PDU_##f: t = #f; break;
      foreach_asn_pdu_id
#undef _

    default:
      return format (s, "unknown 0x%x", id);
    }

  vec_add (s, t, strlen (t));

  return s;
}

always_inline void
asn_crypto_increment_nonce (asn_crypto_state_t * s, asn_rx_or_tx_t rt, u32 increment)
{
  u32 u = increment;
  u32 i;
  for (i = 0; i < ARRAY_LEN (s->nonce); i++)
    {
      u += s->nonce[rt][i];
      s->nonce[rt][i] = u;
      u >>= BITS (s->nonce[rt][i]);
    }
}

typedef struct {
  u8 signature[64];
  u8 contents[32];
} asn_crypto_self_signed_key_t;

static uword
asn_crypto_is_valid_self_signed_key (asn_crypto_self_signed_key_t * ssk, asn_crypto_public_keys_t * public)
{
  u64 tmp_len;
  asn_crypto_self_signed_key_t tmp;
  int r = crypto_sign_open ((u8 *) &tmp, &tmp_len, (u8 *) ssk, sizeof (ssk[0]), public->auth_key);
  if (r >= 0)
    {
      ASSERT (tmp_len == sizeof (tmp.contents));
      ASSERT (! memcmp (tmp.contents, ssk->contents, sizeof (tmp.contents)));
    }
  return r < 0 ? 0 : 1;
}

static void
asn_crypto_create_keys (asn_crypto_public_keys_t * public, asn_crypto_private_keys_t * private)
{
  asn_crypto_self_signed_key_t ssk;
  u64 ssk_len;

  crypto_sign_keypair (public->auth_key, private->auth_key);
  crypto_box_keypair (public->encrypt_key, private->encrypt_key);

  memcpy (ssk.contents, public->encrypt_key, sizeof (ssk.contents));
  ssk_len = sizeof (ssk.contents);
  crypto_sign ((u8 *) &ssk, &ssk_len, public->encrypt_key, ssk_len, private->auth_key);
  ASSERT (ssk_len == sizeof (ssk));
  memcpy (public->self_signed_encrypt_key, ssk.signature, sizeof (public->self_signed_encrypt_key));

  ASSERT (asn_crypto_is_valid_self_signed_key (&ssk, public));
}

#define foreach_asn_session_state               \
  _ (opened)                                    \
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
  /* Previous segments in PDU -- must be full segments of 4094 bytes. */
  asn_pdu_full_segment_t * segments;

  u8 * overflow_buffer;
} asn_pdu_t;

always_inline void
asn_pdu_free (asn_pdu_t * p) 
{
  vec_free (p->segments);
  vec_free (p->overflow_buffer);
}

#if 0
always_inline void
asn_pdu_segmentize_overflow (asn_pdu_t * p)
{
  u32 n_left = vec_len (p->overflow_segment);
  u8 * o = p->overflow_segment;
  while (n_left > 0)
    {
      asn_pdu_full_segment_t * fs;
      u32 n_this_segment;

      vec_add2 (p->segments, fs, 1);

      n_this_segment = n_left > sizeof (fs->data) ? sizeof (fs->data) : n_left;
      fs->n_bytes_in_segment_and_more_flag = 
        clib_host_to_net_u16 (((n_left > sizeof (fs->data)) << ASN_PDU_SEGMENT_HEADER_LOG2_MORE_FLAG)
                              | n_this_segment);
      memcpy (fs->data, o, n_this_segment);
      o += n_this_segment;
      n_left -= n_this_segment;
    }
}

typedef struct {
  /* Index in asn socket pool. */
  u32 index;

  /* Back pointer to websocket. */
  u32 websocket_index;

  asn_session_state_t session_state;

  asn_crypto_ephemeral_keys_t ephemeral_keys;

  /* Nonce and shared secret. */
  asn_crypto_state_t ephemeral_crypto_state;

  /* PDUs to be combined into a single websocket data frame. */
  asn_pdu_t * tx_pdus;

  /* Currently received PDU we're working on. */
  asn_pdu_t rx_pdu;

  /* Hash table which has entries for all user indices logged in on this socket. */
  uword * users_logged_in_this_socket;
} asn_socket_t;

always_inline void
asn_socket_free (asn_socket_t * as)
{
  asn_pdu_t * p;
  asn_pdu_free (&as->rx_pdu);
  vec_foreach (p, as->tx_pdus)
    asn_pdu_free (p);
  vec_free (as->tx_pdus);
  hash_free (as->users_logged_in_this_socket);
}

typedef struct {
  asn_user_t * user_pool;

  uword * user_by_public_encrypt_key;
} asn_known_users_t;

typedef struct asn_main_t {
  websocket_main_t websocket_main;

  unix_file_poller_t unix_file_poller;
  
  /* Server listen config strings of the form IP[:PORT] */
  u8 * server_config;

  asn_crypto_keys_t server_keys;

  u8 * client_config;

  u32 verbose;

  asn_socket_t * socket_pool;

  asn_known_users_t known_users[ASN_N_RX_TX];

  clib_error_t * (* message_was_received) (struct asn_main_t * am, asn_socket_t * as, asn_pdu_t * pdu);

  uword opaque[2];
} asn_main_t;

always_inline void *
asn_socket_tx_add_helper (asn_socket_t * as, u32 n_bytes, uword want_new_pdu)
{
  asn_pdu_t * pdu;
  void * d;

  if (want_new_pdu)
    vec_add2 (as->tx_pdus, pdu, 1);
  else
    pdu = vec_end (as->tx_pdus) - 1;

  d = asn_pdu_add_to_section (pdu, n_bytes, st);

  memset (d, 0, n_bytes);

  return d;
}

always_inline void *
asn_socket_tx_add_header_helper (asn_socket_t * as, asn_pdu_id_t id, u32 n_header_bytes, uword want_new_pdu)
{
  asn_pdu_header_t * h = asn_socket_tx_add_helper (as, n_header_bytes, ASN_PDU_SECTION_TYPE_HEADER, want_new_pdu);
  ASSERT (n_header_bytes >= sizeof (h[0]));
  h->version = 0;
  h->id = id;
  return h;
}

always_inline void *
asn_socket_tx_new_pdu_with_header (asn_socket_t * as, asn_pdu_id_t id, u32 n_header_bytes)
{ return asn_socket_tx_add_header_helper (as, id, n_header_bytes, /* want_new_pdu */ 1); }

always_inline void *
asn_socket_tx_add_header (asn_socket_t * as, asn_pdu_id_t id, u32 n_header_bytes)
{ return asn_socket_tx_add_header_helper (as, id, n_header_bytes, /* want_new_pdu */ 0); }

always_inline void *
asn_socket_tx_new_pdu_with_data (asn_socket_t * as, u32 n_data_bytes)
{ return asn_socket_tx_add_helper (as, n_data_bytes, ASN_PDU_SECTION_TYPE_DATA, /* want_new_pdu */ 1); }

always_inline void *
asn_socket_tx_add_data (asn_socket_t * as, u32 n_data_bytes)
{ return asn_socket_tx_add_helper (as, n_data_bytes, ASN_PDU_SECTION_TYPE_DATA, /* want_new_pdu */ 0); }

void asn_socket_tx (asn_socket_t * as, websocket_socket_t * ws, asn_crypto_state_t * data_crypto_state)
{
  clib_socket_t * s = &ws->clib_socket;
  asn_pdu_t * pdu;
  
  if (vec_len (as->tx_pdus) == 0)
    return;

  vec_foreach (pdu, as->tx_pdus)
    {
      asn_pdu_prologue_t * pp;
      u32 n_bytes_in_section[ASN_PDU_N_SECTION_TYPE];
      u32 n_bytes_in_pdu;
      asn_pdu_section_type_t st;

      foreach_asn_pdu_section_type (st)
      {
        if (st == ASN_PDU_SECTION_TYPE_DATA && vec_len (pdu->sections[st]) == 0)
          n_bytes_in_section[st] = 0;
        else
          {
            ASSERT (vec_len (pdu->sections[st]) >= sizeof (asn_pdu_header_t) + crypto_box_reserved_pad_bytes);
            n_bytes_in_section[st] = vec_len (pdu->sections[st]) - crypto_box_reserved_pad_bytes;
          }
      }

      n_bytes_in_pdu = sizeof (pp[0]);
      foreach_asn_pdu_section_type (st)
        n_bytes_in_pdu += n_bytes_in_section[st];

      pp = clib_socket_tx_add2 (s, n_bytes_in_pdu);

      /* Encrypt and copy encrypted header/data into tx buffer. */
      foreach_asn_pdu_section_type (st)
      {
        asn_crypto_state_t * cs = st == ASN_PDU_SECTION_TYPE_DATA ? data_crypto_state : &as->ephemeral_crypto_state;

        pp->n_bytes_in_section[st] = clib_host_to_net_u32 (n_bytes_in_section[st]);

        if (n_bytes_in_section[st] == 0)
          memset (pp->section_auth[st], 0, sizeof (pp->section_auth[st]));
        else
          {
            if (! cs)
              {
                /* Section is already encrypted or won't be encrypted. */
                ASSERT (st == ASN_PDU_SECTION_TYPE_DATA);
              }
            else
              {
                crypto_box_afternm (pdu->sections[st], pdu->sections[st], vec_len (pdu->sections[st]),
                                    cs->nonce[ASN_TX], cs->shared_secret);
                asn_crypto_increment_nonce (cs, ASN_TX, 2);
              }

            memcpy (pp->section_auth[st],
                    pdu->sections[st] + crypto_box_reserved_pad_authentication_offset,
                    sizeof (pp->section_auth[st]));
            memcpy (pp->header_data
                    + (st == ASN_PDU_SECTION_TYPE_DATA
                       ? n_bytes_in_section[ASN_PDU_SECTION_TYPE_HEADER]
                       : 0),
                    pdu->sections[st] + crypto_box_reserved_pad_bytes,
                    n_bytes_in_section[st]);
          }

        vec_free (pdu->sections[st]);
      }
    }

  vec_reset_length (as->tx_pdus);

  websocket_socket_tx_binary_frame (ws);
}

static u8 * format_asn_session_state (u8 * s, va_list * va)
{
  asn_session_state_t x = va_arg (*va, asn_session_state_t);
  char * t;
  switch (x)
    {
#define _(f) case ASN_SESSION_STATE_##f: t = #f; break;
      foreach_asn_session_state
#undef _

    default:
      return format (s, "unknown 0x%x", x);
    }

  vec_add (s, t, strlen (t));

  return s;
}

u8 * format_asn_socket (u8 * s, va_list * va)
{
  asn_socket_t * as = va_arg (*va, asn_socket_t *);
  
  s = format (s, "session: %U", format_asn_session_state, as->session_state);

  return s;
}

static u8 * format_asn_user_type (u8 * s, va_list * va)
{
  asn_user_type_t x = va_arg (*va, asn_user_type_t);
  char * t;
  switch (x)
    {
#define _(f) case ASN_USER_TYPE_##f: t = #f; break;
      foreach_asn_user_type
#undef _

    default:
      return format (s, "unknown 0x%x", x);
    }

  vec_add (s, t, strlen (t));

  return s;
}

static void
asn_socket_tx_ack_pdu (websocket_main_t * wsm, asn_socket_t * as,
                       void * _request,
                       asn_ack_pdu_status_t status)
{
  asn_pdu_header_t * request = _request;
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_pdu_ack_t * ack;

  ack = asn_socket_tx_new_pdu_with_header (as, ASN_PDU_ack, sizeof (ack[0]));
  ack->request_id = request->id;
  ack->status = status;
  asn_socket_tx (as, ws, /* data_crypto_state */ 0);
}

static clib_error_t *
asn_socket_rx_ack_pdu (websocket_main_t * wsm,
                       asn_socket_t * as,
                       asn_pdu_ack_t * ack)
{
  uword is_error = ack->status != ASN_ACK_PDU_STATUS_success;
  switch (ack->request_id)
    {
    case ASN_PDU_session_login_request:
      if (! is_error)
        as->session_state = ASN_SESSION_STATE_logged_in;
      break;
    }
  return 0;
}

static u8 * format_asn_ack_pdu_status (u8 * s, va_list * va)
{
  asn_ack_pdu_status_t status = va_arg (*va, asn_ack_pdu_status_t);
  char * t = 0;
  switch (status)
    {
#define _(f) case ASN_ACK_PDU_STATUS_##f: t = #f; break;
      foreach_asn_ack_pdu_status
#undef _
    default:
      return format (s, "unknown 0x%x", status);
    }
  s = format (s, "%U", format_c_identifier, t);
  return s;
}

static u8 * format_asn_ack_pdu (u8 * s, va_list * va)
{
  asn_pdu_t * p = va_arg (*va, asn_pdu_t *);
  asn_pdu_ack_t * ack = asn_pdu_get_header (p);

  s = format (s, "request: %U status: %U",
              format_asn_pdu_id, ack->request_id,
              format_asn_ack_pdu_status, ack->status);

  return s;
}

static clib_error_t *
asn_socket_rx_echo_pdu (websocket_main_t * wsm,
                        asn_socket_t * as,
                        asn_pdu_echo_t * req)
{
  asn_pdu_t * p = &as->rx_pdu;

  /* Decrypt data section. */
  {
    asn_pdu_section_type_t st = ASN_PDU_SECTION_TYPE_DATA;
    if (crypto_box_open_afternm (p->sections[st], p->sections[st], vec_len (p->sections[st]),
                                 as->ephemeral_crypto_state.nonce[ASN_RX],
                                 as->ephemeral_crypto_state.shared_secret) < 0)
      return clib_error_return (0, "data authentication fails");
  }

  asn_crypto_increment_nonce (&as->ephemeral_crypto_state, ASN_RX, 2);

  if (! req->is_reply)
    {
      websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
      asn_pdu_echo_t * reply;
      u8 * data;
      u32 i, n_data_bytes;

      reply = asn_socket_tx_new_pdu_with_header (as, ASN_PDU_echo, sizeof (reply[0]));
      reply->is_reply = 1;

      n_data_bytes = as->rx_pdu_n_bytes_in_section[ASN_PDU_SECTION_TYPE_DATA];
      data = asn_socket_tx_add_data (as, n_data_bytes);
      for (i = 0; i < n_data_bytes; i++)
        memcpy (data, asn_pdu_get_data (p), n_data_bytes);

      asn_socket_tx (as, ws, &as->ephemeral_crypto_state);
    }

  return 0;
}

void asn_socket_tx_echo_pdu (websocket_main_t * wsm, asn_socket_t * as)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_pdu_echo_t * echo;
  u8 * data;
  u32 i, n_data_bytes = 64;

  echo = asn_socket_tx_new_pdu_with_header (as, ASN_PDU_echo, sizeof (echo[0]));
  echo->is_reply = 0;
  data = asn_socket_tx_add_data (as, n_data_bytes);
  for (i = 0; i < n_data_bytes; i++)
    data[i] = i;
  asn_socket_tx (as, ws, /* data_crypto_state */ &as->ephemeral_crypto_state);
}

static u8 * format_asn_echo_pdu (u8 * s, va_list * va)
{
  asn_pdu_t * p = va_arg (*va, asn_pdu_t *);
  asn_pdu_echo_t * e = asn_pdu_get_header (p);
  uword indent = format_get_indent (s);
  s = format (s, "%s\n%Udata: %U",
              e->is_reply ? "reply" : "request",
              format_white_space, indent,
              format_hex_bytes, asn_pdu_get_data (p), asn_pdu_data_n_bytes (p));
  return s;
}

always_inline asn_user_t *
asn_main_get_user_by_key (asn_main_t * am, asn_rx_or_tx_t rt, u8 * key)
{
  uword * r = hash_get_mem (am->known_users[rt].user_by_public_encrypt_key, key);
  return r ? pool_elt_at_index (am->known_users[rt].user_pool, r[0]) : 0;
}

static clib_error_t *
asn_socket_rx_session_login_request_pdu (websocket_main_t * wsm,
                                         asn_socket_t * as,
                                         asn_pdu_session_login_request_t * req)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_main_t * am = uword_to_pointer (ws->opaque[0], asn_main_t *);
  asn_user_t * au;
  asn_ack_pdu_status_t status = ASN_ACK_PDU_STATUS_success;
  asn_crypto_self_signed_key_t ssk;

  if (as->session_state != ASN_SESSION_STATE_open)
    {
      status = ASN_ACK_PDU_STATUS_unexpected;
      goto done;
    }

  au = asn_main_get_user_by_key (am, ASN_RX, req->key);
  if (! au)
    {
      status = ASN_ACK_PDU_STATUS_unknown;
      goto done;
    }

  memcpy (ssk.contents, req->key, sizeof (ssk.contents));
  memcpy (ssk.signature, req->signature, sizeof (ssk.signature));

  if (! asn_crypto_is_valid_self_signed_key (&ssk, &au->keys.public))
    status = ASN_ACK_PDU_STATUS_access_denied;

 done:
  if (status == ASN_ACK_PDU_STATUS_success)
    {
      as->session_state = ASN_SESSION_STATE_logged_in;
      if (! au->rx.socket_indices_logged_in_as_this_user)
        au->rx.socket_indices_logged_in_as_this_user = hash_create (0, 0);
      if (! as->users_logged_in_this_socket)
        as->users_logged_in_this_socket = hash_create (0, 0);

      hash_set1 (au->rx.socket_indices_logged_in_as_this_user, as->index);
      hash_set1 (as->users_logged_in_this_socket, au->index);
    }
  asn_socket_tx_ack_pdu (wsm, as, req, status);
  return 0;
}

void asn_socket_tx_session_login_request_pdu (websocket_main_t * wsm, asn_socket_t * as, asn_user_t * au)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_pdu_session_login_request_t * req;

  req = asn_socket_tx_new_pdu_with_header (as, ASN_PDU_session_login_request, sizeof (req[0]));

  memcpy (req->key, au->keys.public.encrypt_key, sizeof (req->key));
  memcpy (req->signature, au->keys.public.self_signed_encrypt_key, sizeof (req->signature));

  asn_socket_tx (as, ws, /* data_crypto_state */ 0);
}

static u8 * format_asn_session_login_request_pdu (u8 * s, va_list * va)
{
  asn_pdu_t * p = va_arg (*va, asn_pdu_t *);
  asn_pdu_session_login_request_t * r = asn_pdu_get_header (p);
  uword indent = format_get_indent (s);
  s = format (s, "key %U\n%Usignature %U",
              format_hex_bytes, r->key, sizeof (r->key),
              format_white_space, indent,
              format_hex_bytes, r->signature, sizeof (r->signature));
  return s;
}

always_inline u8 *
asn_user_key_to_mem (asn_main_t * am, asn_rx_or_tx_t rt, uword k)
{
  asn_user_t * u;
  u8 * m;
  if (k % 2)
    {
      u = pool_elt_at_index (am->known_users[rt].user_pool, k / 2);
      m = u->keys.public.encrypt_key;
    }
  else
    m = uword_to_pointer (k, u8 *);

  return m;
}

static uword
asn_user_by_key_key_sum (hash_t * h, uword key)
{
  asn_main_t * am = uword_to_pointer (h->user &~ 1, asn_main_t *);
  asn_rx_or_tx_t rt = h->user & 1;
  u8 * k = asn_user_key_to_mem (am, rt, key);
  return hash_memory (k, STRUCT_SIZE_OF (asn_user_t, keys.public.encrypt_key), /* hash_seed */ 0);
}

static uword
asn_user_by_key_key_equal (hash_t * h, uword key1, uword key2)
{
  asn_main_t * am = uword_to_pointer (h->user &~ 1, asn_main_t *);
  asn_rx_or_tx_t rt = h->user & 1;
  u8 * k1 = asn_user_key_to_mem (am, rt, key1);
  u8 * k2 = asn_user_key_to_mem (am, rt, key2);
  return 0 == memcmp (k1, k2, STRUCT_SIZE_OF (asn_user_t, keys.public.encrypt_key));
}

static uword
asn_main_new_user_with_type (asn_main_t * am,
                             asn_rx_or_tx_t rt,
                             asn_user_type_t with_user_type,
                             asn_crypto_public_keys_t * with_public_keys)
{
  asn_user_t * au;
  asn_known_users_t * ku = &am->known_users[rt];

  pool_get (ku->user_pool, au);
  au->index = au - ku->user_pool;
  au->user_type = with_user_type;

  if (with_public_keys)
    {
      au->keys.public = with_public_keys[0];
      memset (&au->keys.private, ~0, sizeof (au->keys.private));
      au->private_key_is_valid = 0;
    }
  else
    {
      asn_crypto_create_keys (&au->keys.public, &au->keys.private);
      au->private_key_is_valid = 1;
    }

  if (! ku->user_by_public_encrypt_key)
    ku->user_by_public_encrypt_key
      = hash_create2 (/* elts */ 0,
                      /* user */ pointer_to_uword (am) | rt,
                      /* value_bytes */ sizeof (uword),
                      asn_user_by_key_key_sum,
                      asn_user_by_key_key_equal,
                      /* format pair/arg */
                      0, 0);

  hash_set (ku->user_by_public_encrypt_key, 1 + 2*au->index, au->index);

  return au - ku->user_pool;
}

static clib_error_t *
asn_socket_rx_user_add_request_pdu (websocket_main_t * wsm,
                                         asn_socket_t * as,
                                         asn_pdu_user_add_request_t * req)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_main_t * am = uword_to_pointer (ws->opaque[0], asn_main_t *);
  asn_user_t * au;
  asn_ack_pdu_status_t status = ASN_ACK_PDU_STATUS_success;

  if (req->user_type >= ASN_N_USER_TYPE)
    {
      status = ASN_ACK_PDU_STATUS_failure;
      goto done;
    }

  au = asn_main_get_user_by_key (am, ASN_RX, req->public_encryption_key);
  if (au)
    {
      status = ASN_ACK_PDU_STATUS_failure;
      goto done;
    }

  {
    asn_crypto_public_keys_t k;
    memcpy (k.encrypt_key, req->public_encryption_key, sizeof (k.encrypt_key));
    memcpy (k.auth_key, req->public_authentication_key, sizeof (k.auth_key));
    asn_main_new_user_with_type (am, ASN_RX, req->user_type, /* with_public_keys */ &k);
  }

 done:
  asn_socket_tx_ack_pdu (wsm, as, req, status);
  return 0;
}

void asn_socket_tx_user_add_request_pdu (websocket_main_t * wsm, asn_socket_t * as, asn_user_t * au)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_pdu_user_add_request_t * req;

  req = asn_socket_tx_new_pdu_with_header (as, ASN_PDU_user_add_request, sizeof (req[0]));

  req->user_type = au->user_type;

  memcpy (req->public_encryption_key, au->keys.public.encrypt_key, sizeof (req->public_encryption_key));
  memcpy (req->public_authentication_key, au->keys.public.auth_key, sizeof (req->public_authentication_key));

  asn_socket_tx (as, ws, /* data_crypto_state */ 0);
}

static u8 * format_asn_user_add_request_pdu (u8 * s, va_list * va)
{
  asn_pdu_t * p = va_arg (*va, asn_pdu_t *);
  asn_pdu_user_add_request_t * r = asn_pdu_get_header (p);
  uword indent = format_get_indent (s);
  s = format (s, "type %U\n%Uencrypt key %U\n%Uauth key %U",
              format_asn_user_type, r->user_type,
              format_white_space, indent,
              format_hex_bytes, r->public_encryption_key, sizeof (r->public_encryption_key),
              format_white_space, indent,
              format_hex_bytes, r->public_authentication_key, sizeof (r->public_authentication_key));
  return s;
}

static asn_crypto_state_t *
asn_crypto_state_for_message (asn_user_t * from_user, asn_user_t * to_user)
{
  asn_crypto_state_t * cs;

  if (clib_bitmap_get (from_user->tx.crypto_state_by_user_index_is_valid_bitmap, to_user->index))
    return vec_elt_at_index (from_user->tx.crypto_state_by_user_index, to_user->index);

  vec_validate (from_user->tx.crypto_state_by_user_index, to_user->index);
  from_user->tx.crypto_state_by_user_index_is_valid_bitmap
    = clib_bitmap_ori (from_user->tx.crypto_state_by_user_index_is_valid_bitmap, to_user->index);

  cs = vec_elt_at_index (to_user->tx.crypto_state_by_user_index, to_user->index);

  /* Initialize shared secret and nonce to zero. */
  memset (cs, 0, sizeof (cs[0]));

  /* Must have key for sending user. */
  ASSERT (from_user->private_key_is_valid);

  crypto_box_beforenm (cs->shared_secret, to_user->keys.public.encrypt_key, from_user->keys.private.encrypt_key);

  return cs;
}

static clib_error_t *
asn_socket_rx_message_request_pdu (websocket_main_t * wsm,
                                   asn_socket_t * sup_as,
                                   asn_pdu_message_request_t * sup_req)
{
  websocket_socket_t * sup_ws = pool_elt_at_index (wsm->socket_pool, sup_as->websocket_index);
  asn_main_t * am = uword_to_pointer (sup_ws->opaque[0], asn_main_t *);
  asn_user_t * rxu, * txu;
  asn_ack_pdu_status_t status = ASN_ACK_PDU_STATUS_success;
  uword is_server = websocket_connection_type (sup_ws) == WEBSOCKET_CONNECTION_TYPE_SERVER_CLIENT;
  asn_rx_or_tx_t rt = is_server ? ASN_RX : ASN_TX;
  asn_pdu_t * sup_pdu = &sup_as->rx_pdu;

  txu = asn_main_get_user_by_key (am, rt, sup_req->from_user);
  rxu = asn_main_get_user_by_key (am, rt, sup_req->to_user);

  if (! (txu && rxu))
    {
      status = ASN_ACK_PDU_STATUS_unknown;
      goto done;
    }

  /* For server: relay message to all sockets logged in as to_user. */
  if (is_server)
    {
      hash_pair_t * hp;
      hash_foreach_pair (hp, rxu->rx.socket_indices_logged_in_as_this_user, ({
        asn_socket_t * sub_as;
        websocket_socket_t * sub_ws;
        asn_pdu_message_request_t * sub_req;
        uword asn_socket_index = hp->key;

        sub_as = pool_elt_at_index (am->socket_pool, asn_socket_index);
        sub_ws = pool_elt_at_index (wsm->socket_pool, sub_as->websocket_index);

        sub_req = asn_socket_tx_new_pdu_with_header (sub_as, ASN_PDU_message_request, sizeof (sub_req[0]));
        sub_req[0] = sup_req[0];

        /* Copy message data + authentication. */
        {
          uword n_sup_data = asn_pdu_data_n_bytes (sup_pdu);
          void * sup_data = asn_pdu_get_data (sup_pdu);
          void * sub_data = asn_socket_tx_add_data (sub_as, n_sup_data);
          memcpy (sub_data - crypto_box_authentication_bytes,
                  sup_data - crypto_box_authentication_bytes,
                  n_sup_data + crypto_box_authentication_bytes);
        }

        asn_socket_tx (sub_as, sub_ws, /* data_crypto_state */ 0);
      }));
    }

  /* For client: just receive message. */
  else
    {
      asn_pdu_section_type_t st;
      asn_crypto_state_t * cs;

      /* No key for this user. */
      if (! rxu->private_key_is_valid)
        {
          status = ASN_ACK_PDU_STATUS_unknown;
          goto done;
        }
 
      cs = asn_crypto_state_for_message (rxu, txu);
      st = ASN_PDU_SECTION_TYPE_DATA;
      if (crypto_box_open_afternm (sup_pdu->sections[st], sup_pdu->sections[st], vec_len (sup_pdu->sections[st]),
                                   cs->nonce[ASN_RX],
                                   cs->shared_secret) < 0)
        {
          status = ASN_ACK_PDU_STATUS_access_denied;
          goto done;
        }

      asn_crypto_increment_nonce (cs, ASN_RX, 2);

      am->message_was_received (am, sup_as, sup_pdu);
    }

 done:
  asn_socket_tx_ack_pdu (wsm, sup_as, sup_req, status);
  return 0;
}

void asn_socket_tx_message_request_pdu (websocket_main_t * wsm, asn_socket_t * as,
                                        asn_user_t * txu, asn_user_t * rxu)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_pdu_message_request_t * req;
  asn_crypto_state_t * cs = asn_crypto_state_for_message (txu, rxu);

  req = asn_socket_tx_add_header (as, ASN_PDU_message_request, sizeof (req[0]));

  req->time_stamp_in_nsec = clib_host_to_net_u64 (unix_time_now_nsec ());

  memcpy (req->to_user, rxu->keys.public.encrypt_key, sizeof (req->to_user));

  memcpy (req->from_user, txu->keys.public.encrypt_key, sizeof (req->from_user));

  /* Sender must have valid private key. */
  ASSERT (txu->private_key_is_valid);
  
  asn_socket_tx (as, ws, /* data_crypto_state */ cs);
}

static u8 * format_asn_message_request_pdu (u8 * s, va_list * va)
{
  asn_pdu_t * p = va_arg (*va, asn_pdu_t *);
  asn_pdu_message_request_t * r = asn_pdu_get_header (p);
  uword indent = format_get_indent (s);
  f64 time_stamp_in_sec = 1e-9*clib_net_to_host_u64 (r->time_stamp_in_nsec);
  u32 n_data_bytes = asn_pdu_data_n_bytes (p);
  void * d = asn_pdu_get_data (p);

  s = format (s, "time %U\n%Ufrom %U\n%Uto %U\n%Udata %U",
              format_time_float, /* format */ 0, time_stamp_in_sec,
              format_white_space, indent,
              format_hex_bytes, r->from_user, sizeof (r->from_user),
              format_white_space, indent,
              format_hex_bytes, r->to_user, sizeof (r->to_user),
              format_white_space, indent,
              format_hex_bytes, d, n_data_bytes);
              
  return s;
}

#define _(f)                                                            \
  static clib_error_t *                                                 \
  asn_socket_rx_##f##_pdu (websocket_main_t * wsm, asn_socket_t * as, asn_pdu_header_t * h) \
  { ASSERT (0); return 0; }                                             \
  static u8 * format_asn_##f##_pdu (u8 * s, va_list * va)               \
  { return s; }

_ (raw)
_ (exec)
_ (mark_request)
_ (mark_report)
_ (session_pause_request)
_ (session_quit_request)
_ (session_redirect_request)
_ (session_resume_request)

#undef _

u8 * format_asn_pdu (u8 * s, va_list * va)
{
  asn_pdu_t * p = va_arg (*va, asn_pdu_t *);
  asn_pdu_header_t * h = asn_pdu_get_header (p);

  s = format (s, "%U version %d", format_asn_pdu_id, h->id, h->version);

  switch (h->id)
    {
    default: break;
#define _(f) case ASN_PDU_##f: s = format (s, ", %U", format_asn_##f##_pdu, p); break;
      foreach_asn_pdu_id;
#undef _
    }

  return s;
}

always_inline asn_socket_t *
asn_main_new_socket (asn_main_t * am, u32 websocket_index)
{
  asn_socket_t * as;
  pool_get (am->socket_pool, as);
  memset (as, 0, sizeof (as[0]));
  as->index = as - am->socket_pool;
  as->websocket_index = websocket_index;
  as->session_state = ASN_SESSION_STATE_open;
  return as;
}

clib_error_t *
asn_main_rx_frame_payload (websocket_main_t * wsm, websocket_socket_t * ws, u8 * rx_payload, u32 n_payload_bytes)
{
  asn_main_t * am = uword_to_pointer (ws->opaque[0], asn_main_t *);
  asn_socket_t * as = pool_elt_at_index (am->socket_pool, ws->opaque[1]);
  clib_error_t * error = 0;
  uword n_left = n_payload_bytes;
  u8 * payload = rx_payload;

  while (n_left > 0)
    {
      asn_pdu_prologue_t * pp = (void *) payload;
      asn_pdu_t * p;
      asn_pdu_header_t * h;
      asn_pdu_section_type_t st;
      u32 * n_bytes_in_section = as->rx_pdu_n_bytes_in_section;
      u32 n_bytes_in_pdu;
      uword offset = 0;
      
      foreach_asn_pdu_section_type (st)
        n_bytes_in_section[st] = n_left;

      if (n_left >= sizeof (pp[0]))
        {
          foreach_asn_pdu_section_type (st)
            n_bytes_in_section[st] = clib_net_to_host_u32 (pp->n_bytes_in_section[st]);
        }

      n_bytes_in_pdu = sizeof (pp[0]);
      foreach_asn_pdu_section_type (st)
        n_bytes_in_pdu += n_bytes_in_section[st];

      if (n_bytes_in_section[ASN_PDU_SECTION_TYPE_HEADER] < sizeof (asn_pdu_header_t))
        {
          error = clib_error_return (0, "pdu header length short %d",
                                     n_bytes_in_section[ASN_PDU_SECTION_TYPE_HEADER]);
          goto done;
        }

      if (n_left < n_bytes_in_pdu)
        {
          error = clib_error_return (0, "pdu overflows frame header/data %d + %d > frame %d",
                                     n_bytes_in_section[ASN_PDU_SECTION_TYPE_HEADER],
                                     n_bytes_in_section[ASN_PDU_SECTION_TYPE_DATA],
                                     n_left);
          goto done;
        }

      /* Advance to next pdu in payload. */
      n_left -= n_bytes_in_pdu;
      payload += n_bytes_in_pdu;

      p = &as->rx_pdu;
      asn_pdu_reset (p);
      foreach_asn_pdu_section_type (st)
        {
          if (n_bytes_in_section[st] == 0)
            continue;

          memcpy (asn_pdu_add_to_section (p, n_bytes_in_section[st], st),
                  pp->header_data + offset,
                  n_bytes_in_section[st]);
          offset += n_bytes_in_section[st];

          memcpy (p->sections[st] + crypto_box_reserved_pad_authentication_offset,
                  pp->section_auth[st],
                  sizeof (pp->section_auth[st]));

          if (st == ASN_PDU_SECTION_TYPE_HEADER)
            {
              if (crypto_box_open_afternm (p->sections[st], p->sections[st], vec_len (p->sections[st]),
                                           as->ephemeral_crypto_state.nonce[ASN_RX],
                                           as->ephemeral_crypto_state.shared_secret) < 0)
                {
                  error = clib_error_return (0, "header authentication fails");
                  goto done;
                }

              asn_crypto_increment_nonce (&as->ephemeral_crypto_state, ASN_RX, 2);
            }
        }

      /* Call receive handler for this PDU. */
      h = asn_pdu_get_header (p);
      switch (h->id)
        {
#define _(f)                                                    \
  case ASN_PDU_##f:                                             \
    error = asn_socket_rx_##f##_pdu (wsm, as, (void *) h);      \
    if (error) goto done;                                       \
    break;

          foreach_asn_pdu_id;

#undef _

        default:
          error = clib_error_return (0, "unknown pdu id 0x%x", h->id);
          goto done;
        }

      if (am->verbose)
        clib_warning ("%U %s\n  %U",
                      format_time_float, 0, unix_time_now (),
                      ws->is_server_client ? "client -> server" : "server -> client",
                      format_asn_pdu, p);
    }

 done:
  return error;
}

void asn_main_new_client_for_server (websocket_main_t * wsm, u32 client_ws_index, u32 server_ws_index)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, client_ws_index);
  asn_main_t * am = uword_to_pointer (ws->opaque[0], asn_main_t *);
  asn_socket_t * as;

  as = asn_main_new_socket (am, client_ws_index);

  ws->opaque[1] = as->index;
}

clib_error_t *
asn_main_server_did_receive_handshake (websocket_main_t * wsm, u32 ws_index)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, ws_index);
  http_request_or_response_t * r = &ws->server.http_handshake_request;
  asn_main_t * am = uword_to_pointer (ws->opaque[0], asn_main_t *);
  asn_socket_t * as = pool_elt_at_index (am->socket_pool, ws->opaque[1]);
  u8 * key = 0;

  if (! r->request.path || 0 != strcmp ((char *) r->request.path, "ws/asn"))
    {
      return clib_error_return (0, "unknown http request path `%s'", r->request.path);
    }

  if (! http_request_query_unformat_value_for_key (r, "key", "%U", unformat_hex_string, &key)
      || vec_len (key) != 32)
    {
      clib_error_t * error
        = clib_error_return (0, "invalid or missing key `%U'", format_hex_bytes, key, vec_len (key));
      vec_free (key);
      return error;
    }

  memset (&as->ephemeral_crypto_state, 0, sizeof (as->ephemeral_crypto_state));
  crypto_box_beforenm (as->ephemeral_crypto_state.shared_secret, key, am->server_keys.private.encrypt_key);

  vec_free (key);

  if (am->verbose)
    clib_warning ("request: %U", format_http_request, r);

  return 0;
}

void asn_main_connection_will_close (websocket_main_t * wsm, u32 ws_index, clib_error_t * error_reason)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, ws_index);
  asn_main_t * am = uword_to_pointer (ws->opaque[0], asn_main_t *);
  asn_socket_t * as = pool_elt_at_index (am->socket_pool, ws->opaque[1]);

  if (websocket_connection_type (ws) == WEBSOCKET_CONNECTION_TYPE_SERVER_CLIENT
      && as->session_state == ASN_SESSION_STATE_logged_in)
    {
      hash_pair_t * hp;
      hash_foreach_pair (hp, as->users_logged_in_this_socket, ({
        asn_user_t * au = pool_elt_at_index (am->known_users[ASN_RX].user_pool, hp->key);
        hash_unset (au->rx.socket_indices_logged_in_as_this_user, as->index);
      }));
    }

  asn_socket_free (as);
  pool_put (am->socket_pool, as);

  ws->opaque[1] = ~0;

  if (am->verbose)
    {
      if (error_reason)
        clib_warning ("closing reason: %U", format_clib_error, error_reason);
      else
        clib_warning ("closing end-of-file");
    }
}

clib_error_t * asn_add_connection (asn_main_t * am, u8 * socket_config)
{
  websocket_main_t * wsm = &am->websocket_main;
  websocket_socket_t * ws;
  asn_socket_t * as;
  asn_crypto_ephemeral_keys_t ek;
  u32 client_ws_index;
  clib_error_t * error = 0;

  crypto_box_keypair (ek.public, ek.private);

  error = websocket_client_add_connection (wsm, &client_ws_index,
                                           "ws://%s/ws/asn?key=%U",
                                           socket_config,
                                           format_hex_bytes, ek.public, sizeof (ek.public));
  if (error)
    return error;

  as = asn_main_new_socket (am, client_ws_index);

  ws = pool_elt_at_index (wsm->socket_pool, client_ws_index);
  ws->opaque[0] = pointer_to_uword (am);
  ws->opaque[1] = as->index;

  as->ephemeral_keys = ek;
  crypto_box_beforenm (as->ephemeral_crypto_state.shared_secret,
                       am->server_keys.public.encrypt_key,
                       ek.private);
  return error;
}

clib_error_t * asn_add_listener (asn_main_t * am, u8 * socket_config)
{
  websocket_main_t * wsm = &am->websocket_main;
  websocket_socket_t * ws;
  clib_error_t * error = 0;
  u32 listen_ws_index;

  error = websocket_server_add_listener (wsm, (char *) socket_config, &listen_ws_index);
  if (error)
    return error;

  ws = pool_elt_at_index (wsm->socket_pool, listen_ws_index);
  ws->opaque[0] = pointer_to_uword (am);
  ws->opaque[1] = ~0;

  if (! am->client_config)
    am->client_config = format (0, "%U%c", format_sockaddr, &ws->clib_socket.self_addr, 0);

  asn_crypto_create_keys (&am->server_keys.public, &am->server_keys.private);

  return error;
}

clib_error_t * asn_main_init (asn_main_t * am)
{
  clib_error_t * error = 0;
  websocket_main_t * wsm = &am->websocket_main;

  wsm->unix_file_poller = &am->unix_file_poller;
  wsm->rx_frame_payload = asn_main_rx_frame_payload;
  wsm->new_client_for_server = asn_main_new_client_for_server;
  wsm->connection_will_close = asn_main_connection_will_close;
  wsm->did_receive_handshake = asn_main_server_did_receive_handshake;

  error = websocket_init (wsm);

  return error;
}

typedef struct {
  asn_main_t asn_main;
  
  u32 n_clients;

  u32 n_msgs_sent;
  u32 n_msgs_to_send;
} test_asn_main_t;

typedef struct {
  u8 data[32];
} test_asn_msg_t;

static clib_error_t *
test_asn_main_message_was_received (asn_main_t * am, asn_socket_t * as, asn_pdu_t * pdu)
{
  test_asn_msg_t * msg = asn_pdu_get_data (pdu);
  ASSERT (asn_pdu_data_n_bytes (pdu) == sizeof (msg[0]));
  if (am->verbose)
    clib_warning ("%U", format_hex_bytes, msg->data, sizeof (msg->data));
  return 0;
}

int test_asn_main (unformat_input_t * input)
{
  test_asn_main_t _tm, * tm = &_tm;
  asn_main_t * am = &tm->asn_main;
  websocket_main_t * wsm = &am->websocket_main;
  clib_error_t * error = 0;

  memset (tm, 0, sizeof (tm[0]));
  wsm->verbose = 0;
  am->server_config = (u8 *) "localhost:5000";
  am->client_config = am->server_config;
  am->verbose = 0;
  tm->n_clients = 1;
  tm->n_msgs_to_send = 1;

  am->opaque[0] = pointer_to_uword (tm);
  am->message_was_received = test_asn_main_message_was_received;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "listen %s", &am->server_config))
        ;
      else if (unformat (input, "connect %s", &am->client_config))
        ;
      else if (unformat (input, "n-clients %d", &tm->n_clients))
        ;
      else if (unformat (input, "n-msgs %d", &tm->n_msgs_to_send))
        ;
      else if (unformat (input, "no-listen"))
        {
          am->server_config = 0;
        }
      else if (unformat (input, "verbose"))
        {
          wsm->verbose = 1;
          am->verbose = 1;
        }
      else
        {
          clib_warning ("unknown input `%U'", format_unformat_error, input);
          return 1;
        }
    }

  error = asn_main_init (am);
  if (error)
    goto done;

  if (am->server_config)
    {
      error = asn_add_listener (am, am->server_config);
      if (error)
        goto done;
    }

  {
    int i;
    f64 last_scan_time = unix_time_now ();
    asn_user_t * au;
    u32 asn_user_index;

    asn_user_index = asn_main_new_user_with_type (am, ASN_TX, ASN_USER_TYPE_actual, /* with_public_keys */ 0);

    au = pool_elt_at_index (am->known_users[ASN_TX].user_pool, asn_user_index);

    for (i = 0; i < tm->n_clients; i++)
      {
        error = asn_add_connection (am, am->client_config);
        if (error)
          goto done;
      }

    while (pool_elts (am->unix_file_poller.file_pool) > (am->server_config ? 1 : 0))
      {
        asn_socket_t * as;
        websocket_socket_t * ws;
        f64 now;

        am->unix_file_poller.poll_for_input (&am->unix_file_poller, /* timeout */ 10e-3);

        now = unix_time_now ();

        if (now - last_scan_time > 1)
          {
            websocket_close_all_sockets_with_no_handshake (wsm);

            vec_foreach (as, am->socket_pool)
              {
                if (pool_is_free (am->socket_pool, as))
                  continue;
                ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
                if (websocket_connection_type (ws) == WEBSOCKET_CONNECTION_TYPE_CLIENT)
                  switch (as->session_state)
                    {
                    case ASN_SESSION_STATE_open:
                      asn_socket_tx_user_add_request_pdu (wsm, as, au);
                      asn_socket_tx_session_login_request_pdu (wsm, as, au);
                      break;

                    case ASN_SESSION_STATE_logged_in:
                      if (0)
                        asn_socket_tx_echo_pdu (wsm, as);
                      else
                        {
                          test_asn_msg_t * msg;
                          msg = asn_socket_tx_new_pdu_with_data (as, sizeof (msg[0]));
                          int i;
                          for (i = 0; i < ARRAY_LEN (msg->data); i++)
                            msg->data[i] = i + 1;
                          asn_socket_tx_message_request_pdu (wsm, as, au, au);
                        }
                      break;

                    default:
                      break;
                    }
              }

            last_scan_time += 1;
          }
      }
  }

  unix_file_poller_free (&am->unix_file_poller);

 done:
  if (error)
    clib_error_report (error);
  return error ? 1 : 0;
}

int main (int argc, char * argv[])
{
  unformat_input_t i;
  int ret;

  unformat_init_command_line (&i, argv);
  ret = test_asn_main (&i);
  unformat_free (&i);

  return ret;
}
#endif
