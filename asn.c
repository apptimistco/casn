#include <uclib/uclib.h>
#include <uclib/uclib.c>

#ifndef included_asn_h
#define included_asn_h

#include "tweetnacl.h"

/* Everything ending with _request is acknowledged with an ACK PDU. */
#define foreach_asn_pdu_id                      \
  _ (raw)                                       \
  _ (ack)                                       \
  _ (echo)                                      \
  _ (file_read_and_lock_request)                \
  _ (file_read_no_lock_request)                 \
  _ (file_remove_request)                       \
  _ (file_write_request)                        \
  _ (head_report)                               \
  _ (mark_request)                              \
  _ (mark_report)                               \
  _ (message_request)                           \
  _ (session_login_request)                     \
  _ (session_pause_request)                     \
  _ (session_quit_request)                      \
  _ (session_redirect_request)                  \
  _ (session_resume_request)                    \
  _ (trace_request)                             \
  _ (user_add_request)                          \
  _ (user_del_request)                          \
  _ (user_search_request)                       \
  _ (user_vouch_request)

typedef enum {
#define _(f) ASN_PDU_##f,
  foreach_asn_pdu_id
#undef _
  ASN_N_PDU,
} asn_pdu_id_t;

/* ASN PDUs have header + data sections encrypted with possibly different crypto state. */
typedef enum {
  ASN_PDU_SECTION_TYPE_HEADER,
  ASN_PDU_SECTION_TYPE_DATA,
  ASN_PDU_N_SECTION_TYPE,
} asn_pdu_section_type_t;

#define foreach_asn_pdu_section_type(st) for (st = 0; st < ASN_PDU_N_SECTION_TYPE; st++)

/* Prologue as it appears on the wire. */
typedef CLIB_PACKED (struct {
  /* Header and data (payload) sizes in bytes. */
  u32 n_bytes_in_section[ASN_PDU_N_SECTION_TYPE];

  /* Authentication data for header and data sections. */
  u8 section_auth[ASN_PDU_N_SECTION_TYPE][16];

  u8 header_data[0];
}) asn_pdu_prologue_t;

typedef CLIB_PACKED (struct {
  /* ASN version: set to 0. */
  u8 version;

  /* PDU id. */
  u8 id;

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

  /* ID of request. */
  u8 request_id;

  /* ASN_ACK_PDU_STATUS_* */
  u8 status;
}) asn_pdu_ack_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* 0 for request; non-zero for reply. */
  u8 is_reply;

  /* Data follows.  Number of bytes determined by size of header in prologue. */
  u8 data[0];
}) asn_pdu_echo_t;

#define foreach_asn_user_type \
  _ (actual) _ (forum) _ (bridge)

typedef enum {
#define _(f) ASN_USER_TYPE_##f,
  foreach_asn_user_type
#undef _
  ASN_N_USER_TYPE,
} asn_user_type_t;

#define foreach_asn_user_data_type              \
  _ (name)                                      \
  _ (facebook_id)                               \
  _ (facebook_authentication_token)

typedef enum {
#define _(f) ASN_USER_DATA_##f,
  foreach_asn_user_data_type
#undef _
  ASN_N_USER_DATA_TYPE,
} asn_user_data_type_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* ASN_USER_TYPE_* */
  u8 user_type;

  /* Data associated with user (name, facebook id, ...). */
  u8 user_data_n_bytes[ASN_N_USER_DATA_TYPE];

  /* Encryption and authentication keys for new user. */
  u8 public_encryption_key[32];
  u8 public_authentication_key[32];

  /* User data fields follow. */
  u8 user_data[0];
}) asn_pdu_user_add_request_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* Key for user to delete. */
  u8 key[32];
}) asn_pdu_user_del_request_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* Public encryption key of user. */
  u8 key[32];

  /* ed25519 signature of above key signed by user's private authentication key. */
  u8 signature[64];
}) asn_pdu_session_login_request_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* Public encryption key of user. */
  u8 key[32];

  /* New message head for this user. */
  u8 head[64];
}) asn_pdu_head_report_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* Seconds since Jan 1 1970 UTC. */
  u64 time;

  /* Public keys TO -> FROM. */
  u8 to_user[32];
  u8 from_user[32];
}) asn_pdu_message_request_t;

/* Format of message file TO_USER/messages/HEAD. */
typedef CLIB_PACKED (struct {
  /* ID of previous message (sha512 sum of contents). */
  u8 prev_head[64];

  /* Number of bytes of re-encrypted header that follow. */
  u8 n_header_bytes;

  /* Message header re-encrypted from SELF -> TO. */
  u8 header[0];

  /* Encrypted message data follows.  Encrypted FROM -> TO. */
  u8 data[0];
}) asn_message_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  /* Name follows.  Header length implies size. */
  u8 name[0];
}) asn_pdu_file_request_t;

typedef struct {
  /* Latitude and longitude in degrees.
     Latitude [-180:180]
     Longitude [-90:90]. */
  f64 latitude, longitude;

  /* Elevation in meters. */
  f64 elevation_in_meters;
} asn_location_t;

#define foreach_asn_mark_request_command        \
  _ (set_private_location)                      \
  _ (unset_private_location)                    \
  _ (set_public_location)                       \
  _ (unset_public_location)                     \
  _ (start_scan_of_nearby_users)                \
  _ (stop_scan_of_nearby_users)

typedef enum {
#define _(f) ASN_MARK_REQUEST_COMMAND_##f,
  foreach_asn_mark_request_command
#undef _
  ASN_N_MARK_REQUEST_COMMAND,
} asn_mark_request_command_type_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  asn_location_t location;

  /* ASN_MARK_REQUEST_COMMAND_* */
  u8 command;
}) asn_pdu_mark_request_t;

typedef CLIB_PACKED (struct {
  asn_pdu_header_t header;

  u8 user[32];

  asn_location_t location;
}) asn_pdu_mark_report_t;

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

  s = format (s, "%U", format_c_identifier, t);

  return s;
}

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

typedef struct {
  /* ASN_USER_TYPE_* */
  asn_user_type_t type;

  asn_crypto_keys_t keys;
} asn_user_t;

typedef union {
  /* Header index 0; data index 1. */
  u8 * sections[ASN_PDU_N_SECTION_TYPE];
} asn_pdu_t;

always_inline void *
asn_pdu_add_to_section (asn_pdu_t * p, uword n_bytes, asn_pdu_section_type_t st)
{
  void * result;

  ASSERT (st < ASN_PDU_N_SECTION_TYPE);

  uword n_reserved = vec_len (p->sections[st]) ? 0 : crypto_box_reserved_pad_bytes;

  /* Add extra 32 bytes at start of header or data. */
  n_bytes += n_reserved;

  vec_add2 (p->sections[st], result, n_bytes);

  return result + n_reserved;
}

always_inline void *
asn_pdu_add_header (asn_pdu_t * p, uword n_bytes)
{ return asn_pdu_add_to_section (p, n_bytes, ASN_PDU_SECTION_TYPE_HEADER); }

always_inline void *
asn_pdu_add_data (asn_pdu_t * p, uword n_bytes)
{ return asn_pdu_add_to_section (p, n_bytes, ASN_PDU_SECTION_TYPE_DATA); }

always_inline void *
asn_pdu_get_section (asn_pdu_t * p, asn_pdu_section_type_t st)
{
  if (vec_len (p->sections[st]) == 0)
    return 0;
  return p->sections[st] + crypto_box_reserved_pad_bytes;
}

always_inline u32
asn_pdu_get_section_n_bytes (asn_pdu_t * p, asn_pdu_section_type_t st)
{
  if (vec_len (p->sections[st]) == 0)
    return 0;
  else
    {
      ASSERT (vec_len (p->sections[st]) >= crypto_box_reserved_pad_bytes);
      return vec_len (p->sections[st]) - crypto_box_reserved_pad_bytes;
    }
}

always_inline void *
asn_pdu_get_header (asn_pdu_t * p)
{ return asn_pdu_get_section (p, ASN_PDU_SECTION_TYPE_HEADER); }

always_inline void *
asn_pdu_get_data (asn_pdu_t * p)
{ return asn_pdu_get_section (p, ASN_PDU_SECTION_TYPE_DATA); }

always_inline u32
asn_pdu_header_n_bytes (asn_pdu_t * p)
{ return asn_pdu_get_section_n_bytes (p, ASN_PDU_SECTION_TYPE_HEADER); }

always_inline u32
asn_pdu_data_n_bytes (asn_pdu_t * p)
{ return asn_pdu_get_section_n_bytes (p, ASN_PDU_SECTION_TYPE_DATA); }

always_inline void
asn_pdu_reset (asn_pdu_t * p)
{
  asn_pdu_section_type_t st;
  foreach_asn_pdu_section_type (st)
    vec_reset_length (p->sections[st]);
}

always_inline void
asn_pdu_free (asn_pdu_t * p)
{
  asn_pdu_section_type_t st;
  foreach_asn_pdu_section_type (st)
    vec_free (p->sections[st]);
}

typedef struct {
  /* Index in asn socket pool. */
  u32 index;

  /* Back pointer to websocket. */
  u32 websocket_index;

  u32 asn_user_index;

  asn_crypto_state_t crypto_state;

  /* PDUs to be combined into a single websocket data frame. */
  asn_pdu_t * tx_pdus;

  /* Currently received PDU we're working on. */
  asn_pdu_t rx_pdu;

  /* Prologue for last received PDU. */
  u32 rx_pdu_n_bytes_in_section[ASN_PDU_N_SECTION_TYPE];
} asn_socket_t;

always_inline void
asn_socket_free (asn_socket_t * as)
{
  asn_pdu_t * p;
  asn_pdu_free (&as->rx_pdu);
  vec_foreach (p, as->tx_pdus)
    asn_pdu_free (p);
  vec_free (as->tx_pdus);
}

always_inline void *
asn_socket_tx_add (asn_socket_t * as, asn_pdu_id_t id, u32 header_bytes)
{
  asn_pdu_t * pdu;
  asn_pdu_header_t * h;

  vec_add2 (as->tx_pdus, pdu, 1);

  ASSERT (header_bytes >= sizeof (h[0]));
  h = asn_pdu_add_header (pdu, header_bytes);

  memset (h, 0, header_bytes);

  h->version = 0;
  h->id = id;

  return h;
}

always_inline void *
asn_socket_tx_add_data (asn_socket_t * as, u32 data_bytes)
{
  asn_pdu_t * p = vec_end (as->tx_pdus) - 1;
  return asn_pdu_add_data (p, data_bytes);
}

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
          asn_crypto_state_t * cs = st == ASN_PDU_SECTION_TYPE_DATA ? data_crypto_state : &as->crypto_state;

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

static void asn_socket_tx_ack_pdu (websocket_main_t * wsm, asn_socket_t * as,
                                   void * _request,
                                   asn_ack_pdu_status_t status)
{
  asn_pdu_header_t * request = _request;
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_pdu_ack_t * ack;

  ack = asn_socket_tx_add (as, ASN_PDU_ack, sizeof (ack[0]));
  ack->request_id = request->id;
  ack->status = status;
  asn_socket_tx (as, ws, /* data_crypto_state */ 0);
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
                                 as->crypto_state.nonce[ASN_RX], as->crypto_state.shared_secret) < 0)
      return clib_error_return (0, "data authentication fails");
  }

  asn_crypto_increment_nonce (&as->crypto_state, ASN_RX, 2);

  if (! req->is_reply)
    {
      websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
      asn_pdu_echo_t * reply;
      u8 * data;
      u32 i, n_data_bytes;

      reply = asn_socket_tx_add (as, ASN_PDU_echo, sizeof (reply[0]));
      reply->is_reply = 1;

      n_data_bytes = as->rx_pdu_n_bytes_in_section[ASN_PDU_SECTION_TYPE_DATA];
      data = asn_socket_tx_add_data (as, n_data_bytes);
      for (i = 0; i < n_data_bytes; i++)
        memcpy (data, asn_pdu_get_data (p), n_data_bytes);

      asn_socket_tx (as, ws, &as->crypto_state);
    }

  return 0;
}

void asn_socket_tx_echo_pdu (websocket_main_t * wsm, asn_socket_t * as)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_pdu_echo_t * echo;
  u8 * data;
  u32 i, n_data_bytes = 64;

  echo = asn_socket_tx_add (as, ASN_PDU_echo, sizeof (echo[0]));
  echo->is_reply = 0;
  data = asn_socket_tx_add_data (as, n_data_bytes);
  for (i = 0; i < n_data_bytes; i++)
    data[i] = i;
  asn_socket_tx (as, ws, /* data_crypto_state */ &as->crypto_state);
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

static clib_error_t *
asn_socket_rx_session_login_request_pdu (websocket_main_t * wsm,
                                         asn_socket_t * as,
                                         asn_pdu_session_login_request_t * req)
{
  asn_ack_pdu_status_t status = ASN_ACK_PDU_STATUS_success;
  asn_crypto_self_signed_key_t ssk;
  asn_user_t * au = 0;

  memcpy (ssk.contents, req->key, sizeof (ssk.contents));
  memcpy (ssk.signature, req->signature, sizeof (ssk.signature));

  if (! asn_crypto_is_valid_self_signed_key (&ssk, &au->keys.public))
    status = ASN_ACK_PDU_STATUS_access_denied;

  asn_socket_tx_ack_pdu (wsm, as, req, status);

  return 0;
}

void asn_socket_tx_session_login_request_pdu (websocket_main_t * wsm, asn_socket_t * as, asn_user_t * au)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
  asn_pdu_session_login_request_t * req;

  req = asn_socket_tx_add (as, ASN_PDU_session_login_request, sizeof (req[0]));

  memcpy (req->key, au->keys.public.encrypt_key, sizeof (req->key));
  memcpy (req->signature, au->keys.public.self_signed_encrypt_key, sizeof (req->signature));

  asn_socket_tx (as, ws, /* data_crypto_state */ 0);
}

static u8 * format_asn_session_login_request_pdu (u8 * s, va_list * va)
{
  asn_pdu_t * p = va_arg (*va, asn_pdu_t *);
  asn_pdu_session_login_request_t * r = asn_pdu_get_header (p);
  s = format (s, "key %U signature %U",
              format_hex_bytes, r->key, sizeof (r->key),
              format_hex_bytes, r->signature, sizeof (r->signature));
  return s;
}

#define _(f)                                                            \
  static clib_error_t *                                                 \
    asn_socket_rx_##f##_pdu (websocket_main_t * wsm, asn_socket_t * as, asn_pdu_header_t * h) \
    { ASSERT (0); return 0; }                                           \
  static u8 * format_asn_##f##_pdu (u8 * s, va_list * va)               \
    { return s; }

_ (raw)
_ (ack)
_ (file_read_and_lock_request)
_ (file_read_no_lock_request)
_ (file_remove_request)
_ (file_write_request)
_ (head_report)
_ (mark_request)
_ (mark_report)
_ (message_request)
_ (session_pause_request)
_ (session_quit_request)
_ (session_redirect_request)
_ (session_resume_request)
_ (trace_request)
_ (user_add_request)
_ (user_del_request)
_ (user_search_request)
_ (user_vouch_request)

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

typedef struct {
  websocket_main_t websocket_main;

  unix_file_poller_t unix_file_poller;
  
  /*Server listen config strings of the form IP[:PORT] */
  u8 * server_config;

  asn_crypto_keys_t server_keys;

  u8 * client_config;

  u32 verbose;

  asn_socket_t * asn_socket_pool;

  asn_user_t * asn_user_pool;
} asn_main_t;

always_inline asn_socket_t *
asn_main_new_socket (asn_main_t * am, u32 websocket_index)
{
  asn_socket_t * as;
  pool_get (am->asn_socket_pool, as);
  memset (as, 0, sizeof (as[0]));
  as->index = as - am->asn_socket_pool;
  as->websocket_index = websocket_index;
  as->asn_user_index = ~0;
  return as;
}

typedef struct {
  asn_main_t asn_main;
  
  u32 n_clients;
} test_asn_main_t;

clib_error_t *
asn_main_rx_frame_payload (websocket_main_t * wsm, websocket_socket_t * ws, u8 * rx_payload, u32 n_payload_bytes)
{
  asn_main_t * am = uword_to_pointer (ws->opaque[0], asn_main_t *);
  asn_socket_t * as = pool_elt_at_index (am->asn_socket_pool, ws->opaque[1]);
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
                                           as->crypto_state.nonce[ASN_RX], as->crypto_state.shared_secret) < 0)
                {
                  error = clib_error_return (0, "header authentication fails");
                  goto done;
                }

              asn_crypto_increment_nonce (&as->crypto_state, ASN_RX, 2);
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
  asn_socket_t * as = pool_elt_at_index (am->asn_socket_pool, ws->opaque[1]);
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

  memset (&as->crypto_state, 0, sizeof (as->crypto_state));
  crypto_box_beforenm (as->crypto_state.shared_secret, key, am->server_keys.private.encrypt_key);

  vec_free (key);

  if (am->verbose)
    clib_warning ("request: %U", format_http_request, r);

  return 0;
}

void asn_main_connection_will_close (websocket_main_t * wsm, u32 ws_index, clib_error_t * error_reason)
{
  websocket_socket_t * ws = pool_elt_at_index (wsm->socket_pool, ws_index);
  asn_main_t * am = uword_to_pointer (ws->opaque[0], asn_main_t *);
  asn_socket_t * as = pool_elt_at_index (am->asn_socket_pool, ws->opaque[1]);

  asn_socket_free (as);
  pool_put (am->asn_socket_pool, as);

  ws->opaque[1] = ~0;

  if (am->verbose)
    {
      if (error_reason)
        clib_warning ("closing reason: %U", format_clib_error, error_reason);
      else
        clib_warning ("closing end-of-file");
    }
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

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "listen %s", &am->server_config))
        ;
      else if (unformat (input, "connect %s", &am->client_config))
        ;
      else if (unformat (input, "n-clients %d", &tm->n_clients))
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

  wsm->unix_file_poller = &am->unix_file_poller;
  wsm->rx_frame_payload = asn_main_rx_frame_payload;
  wsm->new_client_for_server = asn_main_new_client_for_server;
  wsm->connection_will_close = asn_main_connection_will_close;
  wsm->did_receive_handshake = asn_main_server_did_receive_handshake;

  error = websocket_init (wsm);
  if (error)
    goto done;

  if (am->server_config)
    {
      u32 listen_ws_index;
      websocket_socket_t * ws;

      error = websocket_server_add_listener (wsm, (char *) am->server_config, &listen_ws_index);
      if (error)
        goto done;

      ws = pool_elt_at_index (wsm->socket_pool, listen_ws_index);
      ws->opaque[0] = pointer_to_uword (am);
      ws->opaque[1] = ~0;

      if (! am->client_config)
        am->client_config = format (0, "%U%c", format_sockaddr, &ws->clib_socket.self_addr, 0);

      asn_crypto_create_keys (&am->server_keys.public, &am->server_keys.private);
    }

  {
    int i;
    asn_user_t * asn_user;
    f64 last_scan_time = unix_time_now ();
    u8 * client_url_path;

    pool_get (am->asn_user_pool, asn_user);
    asn_user->type = ASN_USER_TYPE_actual;
    asn_crypto_create_keys (&asn_user->keys.public, &asn_user->keys.private);

    client_url_path = format (0, "ws://%s/ws/asn?key=%U", am->client_config,
                              format_hex_bytes, asn_user->keys.public.encrypt_key, sizeof (asn_user->keys.public.encrypt_key));

    for (i = 0; i < tm->n_clients; i++)
      {
        u32 client_ws_index;
        asn_socket_t * as;
        websocket_socket_t * ws;

        error = websocket_client_add_connection (wsm, (char *) am->client_config, (char *) client_url_path, &client_ws_index);
        if (error)
          goto done;

        as = asn_main_new_socket (am, client_ws_index);

        ws = pool_elt_at_index (wsm->socket_pool, client_ws_index);
        ws->opaque[0] = pointer_to_uword (tm);
        ws->opaque[1] = as->index;

        as->asn_user_index = asn_user - am->asn_user_pool;

        crypto_box_beforenm (as->crypto_state.shared_secret, am->server_keys.public.encrypt_key, asn_user->keys.private.encrypt_key);
      }

    vec_free (client_url_path);

    while (pool_elts (am->unix_file_poller.file_pool) > (am->server_config ? 1 : 0))
      {
        asn_socket_t * as;
        websocket_socket_t * ws;
        f64 now;

        am->unix_file_poller.poll_for_input (&am->unix_file_poller, 10e-3);

        now = unix_time_now ();

        if (now - last_scan_time > 1)
          {
            websocket_close_all_sockets_with_no_handshake (wsm);

            pool_foreach (as, am->asn_socket_pool, ({
              ws = pool_elt_at_index (wsm->socket_pool, as->websocket_index);
              if (websocket_connection_type (ws) == WEBSOCKET_CONNECTION_TYPE_CLIENT)
                {
                  if (0) asn_socket_tx_echo_pdu (wsm, as);
                  else asn_socket_tx_session_login_request_pdu (wsm, as, asn_user);
                }
            }));

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
