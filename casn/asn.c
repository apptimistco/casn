#include <casn/asn.h>

always_inline void
asn_crypto_increment_nonce (asn_crypto_state_t * s, asn_rx_or_tx_t rt, u32 increment)
{
  u32 u = increment;
  i32 i;
  for (i = ARRAY_LEN (s->nonce[rt]) - 1; i >= 0; i--)
    {
      u += s->nonce[rt][i];
      s->nonce[rt][i] = u;
      u >>= BITS (s->nonce[rt][i]);
    }
}

static void asn_crypto_set_nonce (asn_crypto_state_t * cs, u8 * self_public_key, u8 * peer_public_key,
				  u8 * nonce)
{
  int cmp = memcmp (self_public_key, peer_public_key, STRUCT_SIZE_OF (asn_crypto_ephemeral_keys_t, public));
  int l = sizeof (cs->nonce[ASN_RX]);
  memcpy (cs->nonce[ASN_RX], nonce, l);
  memcpy (cs->nonce[ASN_TX], nonce, l);
  cs->nonce[ASN_TX][l - 2] = 0;
  cs->nonce[ASN_RX][l - 2] = 0;
  cs->nonce[ASN_TX][l - 1] = cmp < 0 ? 1 : 2;
  cs->nonce[ASN_RX][l - 1] = cmp < 0 ? 2 : 1;
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
asn_crypto_create_keys (asn_crypto_public_keys_t * public, asn_crypto_private_keys_t * private, int want_random)
{
  asn_crypto_self_signed_key_t ssk;
  u64 ssk_len;

  crypto_sign_keypair (public->auth_key, private->auth_key, want_random);
  crypto_box_keypair (public->encrypt_key, private->encrypt_key, want_random);

  memcpy (ssk.contents, public->encrypt_key, sizeof (ssk.contents));
  ssk_len = sizeof (ssk.contents);
  crypto_sign ((u8 *) &ssk, &ssk_len, public->encrypt_key, ssk_len, private->auth_key);
  ASSERT (ssk_len == sizeof (ssk));
  memcpy (public->self_signed_encrypt_key, ssk.signature, sizeof (public->self_signed_encrypt_key));

  ASSERT (asn_crypto_is_valid_self_signed_key (&ssk, public));
}

always_inline u8 *
asn_user_key_to_mem (asn_main_t * am, asn_rx_or_tx_t rt, uword k)
{
  asn_user_t * u;
  u8 * m;
  if (k % 2)
    {
      u = pool_elt_at_index (am->known_users[rt].user_pool, k / 2);
      m = u->crypto_keys.public.encrypt_key;
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
  return hash_memory (k, STRUCT_SIZE_OF (asn_user_t, crypto_keys.public.encrypt_key), /* hash_seed */ 0);
}

static uword
asn_user_by_key_key_equal (hash_t * h, uword key1, uword key2)
{
  asn_main_t * am = uword_to_pointer (h->user &~ 1, asn_main_t *);
  asn_rx_or_tx_t rt = h->user & 1;
  u8 * k1 = asn_user_key_to_mem (am, rt, key1);
  u8 * k2 = asn_user_key_to_mem (am, rt, key2);
  return 0 == memcmp (k1, k2, STRUCT_SIZE_OF (asn_user_t, crypto_keys.public.encrypt_key));
}

uword
asn_main_new_user_with_type (asn_main_t * am,
                             asn_rx_or_tx_t rt,
                             asn_user_type_t with_user_type,
                             asn_crypto_public_keys_t * with_public_keys,
			     asn_crypto_private_keys_t * with_private_keys)
{
  asn_user_t * au;
  asn_known_users_t * ku = &am->known_users[rt];
  asn_crypto_keys_t * k;

  pool_get (ku->user_pool, au);
  au->index = au - ku->user_pool;
  au->user_type = with_user_type;
  k = &au->crypto_keys;

  if (with_public_keys)
    {
      /* With public keys implies that private keys are invalid. */
      k->public = with_public_keys[0];
      memset (&k->private, ~0, sizeof (k->private));
      au->private_key_is_valid = 0;
    }
  else
    {
      /* Private keys specified? */
      if (with_private_keys)
	{
	  memcpy (&k->private.encrypt_key, with_private_keys->encrypt_key, sizeof (k->private.encrypt_key));
	  memcpy (&k->private.auth_key, with_private_keys->auth_key, 32);
	  asn_crypto_create_keys (&k->public, &k->private, /* want_random */ 0);
	}
      else
	/* Random private keys. */
	asn_crypto_create_keys (&k->public, &k->private, /* want_random */ 1);

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

u8 * format_asn_user_type (u8 * s, va_list * va)
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

u8 * format_asn_user (u8 * s, va_list * va)
{
  asn_user_t * au = va_arg (*va, asn_user_t *);
  
  s = format (s, "type: %U", format_asn_user_type, au->user_type);

  return s;
}

static void
asn_pdu_sync_overflow (asn_pdu_t * p)
{
  u32 n_left_overflow = vec_len (p->overflow_data);
  u32 n_left_this_frame;
  asn_pdu_frame_t * f = &p->last_frame;

  ASSERT (p->n_user_bytes_in_last_frame <= sizeof (f->user_data));
  n_left_this_frame = sizeof (f->user_data) - p->n_user_bytes_in_last_frame;
  while (n_left_overflow > 0)
    {
      u32 n_copy_this_frame = clib_min (n_left_overflow, n_left_this_frame);
      memcpy (f->user_data + p->n_user_bytes_in_last_frame, p->overflow_data, n_copy_this_frame);
      n_left_this_frame -= n_copy_this_frame;
      n_left_overflow -= n_copy_this_frame;
      vec_delete (p->overflow_data, n_copy_this_frame, 0);
      if (n_left_this_frame == 0)
        {
          f->n_user_data_bytes = sizeof (f->user_data);
          vec_add1 (p->full_frames, p->last_frame);
          n_left_this_frame = sizeof (f->user_data);
          p->n_user_bytes_in_last_frame = 0;
        }
    }

  p->n_user_bytes_in_last_frame = sizeof (f->user_data) - n_left_this_frame;
  vec_reset_length (p->overflow_data);
}

static void *
asn_socket_tx_add (asn_socket_t * as, u32 n_bytes, uword want_new_pdu)
{
  asn_pdu_t * p;
  asn_pdu_frame_t * f;
  void * d;
  u32 n_left_this_frame;

  if (want_new_pdu)
    vec_add2 (as->tx_pdus, p, 1);
  else
    p = vec_end (as->tx_pdus) - 1;

  f = &p->last_frame;
  n_left_this_frame = sizeof (f->user_data) - p->n_user_bytes_in_last_frame;
  if (n_bytes <= n_left_this_frame && vec_len (p->overflow_data) == 0)
    {
      d = f->user_data + p->n_user_bytes_in_last_frame;
      p->n_user_bytes_in_last_frame += n_bytes;
    }
  else
    {
      vec_resize (p->overflow_data, n_bytes);
      d = vec_end (p->overflow_data) - n_bytes;
    }

  memset (d, 0, n_bytes);
  return d;
}

always_inline void *
asn_socket_tx_add_pdu (asn_socket_t * as, asn_pdu_id_t id, u32 n_header_bytes)
{
  asn_pdu_header_t * h = asn_socket_tx_add (as, n_header_bytes, /* want_new_pdu */ 1);
  ASSERT (n_header_bytes >= sizeof (h[0]));
  memset (h, 0, sizeof (h[0]));
  h->version = 0;
  h->id = id;
  h->casn_request_id.id = id;	/* remote will echo */
  return h;
}

always_inline void
asn_socket_tx_add_data (asn_socket_t * as, void * data, uword n_data_bytes)
{
  void * d = asn_socket_tx_add (as, n_data_bytes, /* want_new_pdu */ 1);
  memcpy (d, data, n_data_bytes);
}

static clib_error_t * asn_socket_transmit_frame (asn_socket_t * as, asn_pdu_frame_t * f, uword n_user_data_bytes, uword is_last_frame)
{
  websocket_socket_t * ws = &as->websocket_socket;
  asn_crypto_state_t * cs = &as->ephemeral_crypto_state;
  u8 crypto_box_buffer[crypto_box_reserved_pad_bytes + sizeof (f->user_data)];

  ASSERT (n_user_data_bytes <= sizeof (f->user_data));

  memset (crypto_box_buffer, 0, crypto_box_reserved_pad_bytes);
  memcpy (crypto_box_buffer + crypto_box_reserved_pad_bytes, f->user_data, n_user_data_bytes);

  crypto_box_afternm (crypto_box_buffer, crypto_box_buffer, crypto_box_reserved_pad_bytes + n_user_data_bytes,
		      cs->nonce[ASN_TX], cs->shared_secret);
  asn_crypto_increment_nonce (cs, ASN_TX, 2);

  /* Copy in authenticator + encrypted user data. */
  memcpy (f->user_data_authentication, crypto_box_buffer + crypto_box_reserved_pad_authentication_offset,
	  sizeof (f->user_data_authentication));
  memcpy (f->user_data, crypto_box_buffer + crypto_box_reserved_pad_bytes, n_user_data_bytes);

  f->n_bytes_that_follow_and_more_flag_network_byte_order
    = clib_host_to_net_u16 ((n_user_data_bytes + sizeof (f->user_data_authentication))
			    | ((is_last_frame == 0) << ASN_PDU_FRAME_LOG2_MORE_FLAG));

  clib_socket_tx_add (&ws->clib_socket, f, STRUCT_OFFSET_OF (asn_pdu_frame_t, user_data) + n_user_data_bytes);
  return websocket_socket_tx_binary_frame (ws);
}

static clib_error_t *
asn_socket_transmit_and_reset_pdu (asn_socket_t * as, asn_pdu_t * pdu)
{
  asn_pdu_frame_t * f;
  clib_error_t * error;

  asn_pdu_sync_overflow (pdu);

  vec_foreach (f, pdu->full_frames)
    {
      error = asn_socket_transmit_frame (as, f, f->n_user_data_bytes, /* is_last_frame */ 0);
      if (error)
	goto done;
    }

  error = asn_socket_transmit_frame (as, &pdu->last_frame, pdu->n_user_bytes_in_last_frame, /* is_last_frame */ 1);

 done:
  asn_pdu_free (pdu);
  pdu->n_user_bytes_in_last_frame = 0;

  return error;
}

clib_error_t * asn_socket_tx (asn_socket_t * as)
{
  clib_error_t * error;
  asn_pdu_t * pdu;
  vec_foreach (pdu, as->tx_pdus)
    {
      error = asn_socket_transmit_and_reset_pdu (as, pdu);
      if (error)
	break;
    }
  vec_reset_length (as->tx_pdus);
  return error;
}

clib_error_t * asn_exec (asn_socket_t * as,
			 asn_ack_handler_t * ack_handler,
			 char * fmt, ...)
{
  va_list va;
  u8 * s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  asn_pdu_header_t * h = asn_socket_tx_add_pdu (as, ASN_PDU_exec, sizeof (h[0]) + vec_len (s));
  memcpy (h->data, s, vec_len (s));
  vec_free (s);

  {
    asn_ack_handler_t ** ah;
    pool_get (as->ack_handler_pool, ah);
    ah[0] = ack_handler;
    h->casn_request_id.ack_handler_index = ah - as->ack_handler_pool;
  }

  return asn_socket_tx (as);
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

#if 0
static clib_error_t *
asn_socket_tx_ack_pdu (asn_main_t * am, asn_socket_t * as, asn_ack_pdu_status_t status)
{
  asn_pdu_ack_t * ack = asn_socket_tx_add_pdu (as, ASN_PDU_ack, sizeof (ack[0]));
  ack->status = status;
  return asn_socket_tx (as);
}
#endif

static void asn_socket_crypto_set_peer (asn_socket_t * as, u8 * peer_public_key, u8 * peer_nonce)
{
  asn_crypto_state_t * cs = &as->ephemeral_crypto_state;
  asn_crypto_ephemeral_keys_t * ek = &as->ephemeral_keys;

  crypto_box_beforenm (cs->shared_secret, peer_public_key, ek->private);
  asn_crypto_set_nonce (cs, ek->public, peer_public_key, peer_nonce);
}

static clib_error_t *
asn_socket_rx_ack_pdu (asn_main_t * am,
                       asn_socket_t * as,
                       asn_pdu_ack_t * ack,
		       uword n_bytes_in_pdu)
{
  clib_error_t * error = 0;
  uword is_error = ack->status != ASN_ACK_PDU_STATUS_success;
  asn_pdu_id_t acked_pdu_id = ack->header.casn_request_id.id;

  switch (acked_pdu_id)
    {
    case ASN_PDU_login:
    case ASN_PDU_resume: {
      if (! is_error && acked_pdu_id == ASN_PDU_login)
	as->session_state = ASN_SESSION_STATE_established;

      /* Login/resume response contains new emphemeral public key and nonce. */
      {
	struct {
	  u8 public_encrypt_key[crypto_box_public_key_bytes];
	  u8 nonce[crypto_box_nonce_bytes];
	} * rekey = (void *) ack->data;
	asn_socket_crypto_set_peer (as, rekey->public_encrypt_key, rekey->nonce);
      }

      break;
    }

    case ASN_PDU_exec: {
      u32 ai = ack->header.casn_request_id.ack_handler_index;
      asn_ack_handler_t * ah;

      if (pool_is_free_index (as->ack_handler_pool, ai))
	{
	  error = clib_error_return (0, "unknown ack handler with index 0x%x", ai);
	  goto done;
	}

      ah = as->ack_handler_pool[ai];
      pool_put_index (as->ack_handler_pool, ai);
      return ah (am, as, ack, n_bytes_in_pdu - sizeof (ack[0]));
    }

    default:
      ASSERT (0);
      break;
    }

 done:
  return error;
}

static u8 * format_asn_pdu_id (u8 * s, va_list * va)
{
  asn_pdu_id_t id = va_arg (*va, asn_pdu_id_t);
  char * t;
  switch (id)
    {
#define _(f,n) case ASN_PDU_##f: t = #f; break;
      foreach_asn_pdu_id
#undef _

    default:
      return format (s, "unknown 0x%x", id);
    }

  vec_add (s, t, strlen (t));

  return s;
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
  asn_pdu_ack_t * ack = va_arg (*va, asn_pdu_ack_t *);
  u32 n_bytes = va_arg (*va, u32);

  s = format (s, "request: %U, status: %U",
              format_asn_pdu_id, ack->header.casn_request_id.id,
              format_asn_ack_pdu_status, ack->status);

  if (n_bytes > sizeof (ack[0]))
    s = format (s, ", data %U", format_hex_bytes, ack->data, n_bytes - sizeof (ack[0]));

  return s;
}

#if 0
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

  crypto_box_beforenm (cs->shared_secret, to_user->crypto_keys.public.encrypt_key, from_user->crypto_keys.private.encrypt_key);

  return cs;
}
#endif

#define _(f)                                                            \
  static clib_error_t *                                                 \
    asn_socket_rx_##f##_pdu (asn_main_t * am, asn_socket_t * as, asn_pdu_header_t * h, u32 n_bytes_in_pdu) \
  { ASSERT (0); return 0; }                                             \
  static u8 * format_asn_##f##_pdu (u8 * s, va_list * va)               \
  { return s; }

_ (exec)
_ (login)
_ (pause)
_ (quit)
_ (redirect)
_ (resume)
_ (blob)
_ (index)

#undef _

u8 * format_asn_pdu (u8 * s, va_list * va)
{
  asn_pdu_header_t * h = va_arg (*va, asn_pdu_header_t *);
  u32 n_bytes = va_arg (*va, u32);

  s = format (s, "%U version %d", format_asn_pdu_id, h->id, h->version);

  switch (h->id)
    {
    default: break;
#define _(f,n) case ASN_PDU_##f: s = format (s, ", %U", format_asn_##f##_pdu, h, n_bytes); break;
      foreach_asn_pdu_id;
#undef _
    }

  return s;
}

clib_error_t * asn_socket_login_for_user (asn_socket_t * as, asn_user_t * au)
{
  asn_pdu_login_t * l;
  l = asn_socket_tx_add_pdu (as, ASN_PDU_login, sizeof (l[0]));
  memcpy (l->key, au->crypto_keys.public.encrypt_key, sizeof (l->key));
  memcpy (l->signature, au->crypto_keys.public.self_signed_encrypt_key, sizeof (l->signature));
  return asn_socket_tx (as);
}

static clib_error_t *
asn_main_rx_frame_payload (websocket_main_t * wsm, websocket_socket_t * ws, u8 * rx_payload, u32 n_payload_bytes)
{
  asn_main_t * am = CONTAINER_OF (wsm, asn_main_t, websocket_main);
  asn_socket_t * as = CONTAINER_OF (ws, asn_socket_t, websocket_socket);
  clib_error_t * error = 0;
  asn_pdu_frame_t * f;
  u8 crypto_box_buffer[crypto_box_reserved_pad_bytes + sizeof (f->user_data)];
  u32 n_user_data_bytes, l, is_last_frame, is_server;
  
  is_server = websocket_connection_type (ws) == WEBSOCKET_CONNECTION_TYPE_server_client;

  if (is_server && as->session_state == ASN_SESSION_STATE_opened)
    {
      as->session_state = ASN_SESSION_STATE_established;
      if (n_payload_bytes != sizeof (as->ephemeral_keys.public))
	{
	  error = clib_error_return (0, "expected public key %d bytes received %d bytes",
				     sizeof (as->ephemeral_keys.public), n_payload_bytes);
	  goto done;
	}

      memcpy (as->ephemeral_crypto_state.nonce, am->server_nonce, sizeof (am->server_nonce));
      crypto_box_beforenm (as->ephemeral_crypto_state.shared_secret, rx_payload, am->server_keys.private.encrypt_key);

      /* FIXME ack with our ephemeral key and new nonce. */

      if (am->verbose)
	clib_warning ("handshake received; ephemeral received %U",
		      format_hex_bytes, rx_payload, sizeof (as->ephemeral_keys.public));

      return 0;
    }

  vec_add (as->rx_pdu, rx_payload, n_payload_bytes);
  f = (void *) as->rx_pdu;

  l = clib_net_to_host_u16 (f->n_bytes_that_follow_and_more_flag_network_byte_order);
  is_last_frame = (l & ASN_PDU_FRAME_MORE_FLAG) == 0;
  l &= ~ ASN_PDU_FRAME_MORE_FLAG;

  if (vec_len (as->rx_pdu) < l + sizeof (f->n_bytes_that_follow_and_more_flag_network_byte_order))
    return 0;

  if (vec_len (as->rx_pdu) > l + sizeof (f->n_bytes_that_follow_and_more_flag_network_byte_order))
    {
      error = clib_error_return (0, "frame length error frame %d websocket %d", l, n_payload_bytes);
      goto done;
    }

  n_user_data_bytes = vec_len (as->rx_pdu) - STRUCT_OFFSET_OF (asn_pdu_frame_t, user_data);
  if (n_user_data_bytes > sizeof (f->user_data))
    {
      error = clib_error_return (0, "frame length too long %d", n_user_data_bytes);
      goto done;
    }

  memset (crypto_box_buffer, 0, crypto_box_reserved_pad_authentication_offset);
  memcpy (crypto_box_buffer + crypto_box_reserved_pad_authentication_offset,
	  f->user_data_authentication,
	  sizeof (f->user_data_authentication));
  memcpy (crypto_box_buffer + crypto_box_reserved_pad_bytes, f->user_data, n_user_data_bytes);

  vec_reset_length (as->rx_pdu);

  if (crypto_box_open_afternm (crypto_box_buffer, crypto_box_buffer, crypto_box_reserved_pad_bytes + n_user_data_bytes,
			       as->ephemeral_crypto_state.nonce[ASN_RX],
			       as->ephemeral_crypto_state.shared_secret) < 0)
    {
      error = clib_error_return (0, "authentication fails");
      goto done;
    }
  asn_crypto_increment_nonce (&as->ephemeral_crypto_state, ASN_RX, 2);

  vec_add (as->rx_pdu, crypto_box_buffer + crypto_box_reserved_pad_bytes, n_user_data_bytes);

  if (! is_last_frame)
    goto done;

  if (vec_len (as->rx_pdu) < sizeof (asn_pdu_header_t))
    {
      error = clib_error_return (0, "short pdu %d bytes", vec_len (as->rx_pdu));
      goto done;
    }

  asn_pdu_header_t * h = (void *) as->rx_pdu;

  if (am->verbose)
    clib_warning ("%U %s\n  %U",
		  format_time_float, 0, unix_time_now (),
		  ws->is_server_client ? "client -> server" : "server -> client",
		  format_asn_pdu, h, vec_len (as->rx_pdu));

  switch (h->id)
    {
#define _(f,n)								\
  case ASN_PDU_##f:							\
    error = asn_socket_rx_##f##_pdu (am, as, (void *) h, vec_len (as->rx_pdu)); \
    if (error) goto done;						\
    break;

          foreach_asn_pdu_id;

#undef _

    default:
      error = clib_error_return (0, "unknown pdu id 0x%x", h->id);
      goto done;
    }

 done:
  vec_reset_length (as->rx_pdu);
  return error;
}

static void asn_main_new_client_for_server (websocket_main_t * wsm, websocket_socket_t * ws, websocket_socket_t * server_ws)
{
  // asn_main_t * am = CONTAINER_OF (wsm, asn_main_t, websocket_main);
  asn_socket_t * as = CONTAINER_OF (ws, asn_socket_t, websocket_socket);
  as->session_state = ASN_SESSION_STATE_opened;
}

static clib_error_t *
asn_main_did_receive_handshake (websocket_main_t * wsm, websocket_socket_t * ws)
{
  asn_main_t * am = CONTAINER_OF (wsm, asn_main_t, websocket_main);
  asn_socket_t * as = CONTAINER_OF (ws, asn_socket_t, websocket_socket);
  clib_error_t * error = 0;

  if (websocket_connection_type (ws) == WEBSOCKET_CONNECTION_TYPE_server_client)
    {
      http_request_or_response_t * r = &ws->server.http_handshake_request;

      if (! r->request.path || 0 != strcmp ((char *) r->request.path, "/asn/siren.ws"))
	{
	  error = clib_error_return (0, "unknown http request path `%s'", r->request.path);
	  goto done;
	}

      if (am->verbose)
	clib_warning ("request: %U", format_http_request, r);
    }
  else
    {
      asn_crypto_ephemeral_keys_t * ek = &as->ephemeral_keys;

      clib_socket_tx_add (&ws->clib_socket, ek->public, sizeof (ek->public));
      error = websocket_socket_tx_binary_frame (ws);
      if (error)
	goto done;

      if (! pool_is_free_index (am->known_users[ASN_TX].user_pool, am->self_user_index))
	{
	  asn_user_t * au = pool_elt_at_index (am->known_users[ASN_TX].user_pool, am->self_user_index);
	  error = asn_socket_login_for_user (as, au);
	  if (error)
	    goto done;
	}

      if (am->verbose)
	clib_warning ("handshake received; ephemeral sent %U", format_hex_bytes, ek->public, sizeof (ek->public));
    }

 done:
  return error;
}

static void asn_main_connection_will_close (websocket_main_t * wsm, websocket_socket_t * ws, clib_error_t * error_reason)
{
  asn_main_t * am = CONTAINER_OF (wsm, asn_main_t, websocket_main);
  asn_socket_t * as = CONTAINER_OF (ws, asn_socket_t, websocket_socket);

  asn_socket_free (as);

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
  clib_error_t * error = 0;

  error = websocket_client_add_connection (wsm, &ws, "ws://%s/asn/siren.ws", socket_config);
  if (error)
    return error;

  as = CONTAINER_OF (ws, asn_socket_t, websocket_socket);

  {
    asn_crypto_ephemeral_keys_t ek;

    if (1)
      crypto_box_keypair (ek.public, ek.private, /* want_random */ 1);
    else
      {
	/* Zero key for testing. */
	memset (ek.private, 0, sizeof (ek.private));
	crypto_box_keypair (ek.public, ek.private, /* want_random */ 0);
      }

    as->ephemeral_keys = ek;
  }

  asn_socket_crypto_set_peer (as, am->server_keys.public.encrypt_key, am->server_nonce);

  return error;
}

clib_error_t * asn_add_listener (asn_main_t * am, u8 * socket_config, int want_random_keys)
{
  websocket_main_t * wsm = &am->websocket_main;
  websocket_socket_t * ws;
  clib_error_t * error = 0;

  error = websocket_server_add_listener (wsm, (char *) socket_config, &ws);
  if (error)
    return error;

  if (! am->client_config)
    am->client_config = format (0, "%U%c", format_sockaddr, &ws->clib_socket.self_addr, 0);

  ASSERT (want_random_keys);
  asn_crypto_create_keys (&am->server_keys.public, &am->server_keys.private, want_random_keys);

  return error;
}

clib_error_t * asn_main_init (asn_main_t * am, u32 user_socket_n_bytes, u32 user_socket_offset_of_asn_socket)
{
  clib_error_t * error = 0;
  websocket_main_t * wsm = &am->websocket_main;

  wsm->user_socket_n_bytes = user_socket_n_bytes;
  wsm->user_socket_offset_of_websocket = user_socket_offset_of_asn_socket + STRUCT_OFFSET_OF (asn_socket_t, websocket_socket);

  wsm->unix_file_poller = &am->unix_file_poller;
  wsm->new_client_for_server = asn_main_new_client_for_server;
  wsm->connection_will_close = asn_main_connection_will_close;
  wsm->rx_frame_payload = asn_main_rx_frame_payload;
  wsm->did_receive_handshake = asn_main_did_receive_handshake;

  error = websocket_init (wsm);

  return error;
}
