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
      u = asn_user_by_ref_as_uword (k / 2);
      m = u->crypto_keys.public.encrypt_key;
    }
  else
    m = uword_to_pointer (k, u8 *);

  return m;
}

static uword
asn_user_key_sum (hash_t * h, uword key, uword n_key_bytes)
{
  asn_main_t * am = uword_to_pointer (h->user &~ 1, asn_main_t *);
  asn_rx_or_tx_t rt = h->user & 1;
  u8 * k = asn_user_key_to_mem (am, rt, key);
  ASSERT (n_key_bytes <= STRUCT_SIZE_OF (asn_user_t, crypto_keys.public.encrypt_key));
  return hash_memory (k, n_key_bytes, /* hash_seed */ 0);
}

static uword
asn_user_key_sum_full (hash_t * h, uword key)
{ return asn_user_key_sum (h, key, STRUCT_SIZE_OF (asn_user_t, crypto_keys.public.encrypt_key)); }

static uword
asn_user_key_sum_7 (hash_t * h, uword key)
{ return asn_user_key_sum (h, key, 7); }

static uword
asn_user_key_sum_8 (hash_t * h, uword key)
{ return asn_user_key_sum (h, key, 8); }

static uword
asn_user_key_equal (hash_t * h, uword key1, uword key2, uword n_key_bytes)
{
  asn_main_t * am = uword_to_pointer (h->user &~ 1, asn_main_t *);
  asn_rx_or_tx_t rt = h->user & 1;
  u8 * k1 = asn_user_key_to_mem (am, rt, key1);
  u8 * k2 = asn_user_key_to_mem (am, rt, key2);
  ASSERT (n_key_bytes <= STRUCT_SIZE_OF (asn_user_t, crypto_keys.public.encrypt_key));
  return 0 == memcmp (k1, k2, n_key_bytes);
}

static uword
asn_user_key_equal_full (hash_t * h, uword key1, uword key2)
{ return asn_user_key_equal (h, key1, key2, STRUCT_SIZE_OF (asn_user_t, crypto_keys.public.encrypt_key)); }

static uword
asn_user_key_equal_7 (hash_t * h, uword key1, uword key2)
{ return asn_user_key_equal (h, key1, key2, 7); }

static uword
asn_user_key_equal_8 (hash_t * h, uword key1, uword key2)
{ return asn_user_key_equal (h, key1, key2, 8); }

asn_user_t *
asn_update_peer_user (asn_main_t * am, asn_rx_or_tx_t rt, u32 user_type_index, u8 * encrypt_key, u8 * auth_key)
{
  asn_user_t * au = asn_user_with_encrypt_key (am, rt, encrypt_key);
  if (! au)
    {
      asn_crypto_public_keys_t pk;
      memcpy (pk.encrypt_key, encrypt_key, sizeof (pk.encrypt_key));
      memcpy (pk.auth_key, auth_key, sizeof (pk.auth_key));
      au = asn_new_user_with_type (am, rt, user_type_index, &pk, /* private keys */ 0, /* with_random_private_keys */ 0);
    }

  if (auth_key)
    memcpy (au->crypto_keys.public.auth_key, auth_key, sizeof (au->crypto_keys.public.auth_key));

  return au;
}

static void asn_user_hash_value_free (uword v)
{
  asn_user_hash_value_t hv;
  hv.as_uword = v;
  if (! hv.is_inline)
    vec_free (hv.value_vector);
}

static void asn_user_hash_value_update (asn_user_hash_value_t * hv, uword value_to_add)
{
  uword * v = 0;
  if (hv->is_inline)
    vec_add1 (v, hv->inline_value);
  else
    v = hv->value_vector;

  vec_add1 (v, value_to_add);
  hv->value_vector = v;
}

static void asn_user_hash_by_public_key (asn_main_t * am, asn_rx_or_tx_t rt, asn_user_t * au)
{
  uword k, * p;
  asn_user_hash_value_t hv;
  asn_user_ref_t r;
  asn_crypto_keys_t * ck;
  uword r_as_uword;

  ck = &au->crypto_keys;

  if (! am->user_ref_by_public_encrypt_key[rt])
    {
      am->user_ref_by_public_encrypt_key[rt]
	= hash_create2 (/* elts */ 0,
			/* user */ pointer_to_uword (am) | rt,
			/* value_bytes */ sizeof (uword),
			asn_user_key_sum_full,
			asn_user_key_equal_full,
			/* format pair/arg */
			0, 0);
      am->user_ref_by_public_encrypt_key_first_7_bytes[rt]
	= hash_create2 (/* elts */ 0,
			/* user */ pointer_to_uword (am) | rt,
			/* value_bytes */ sizeof (asn_user_hash_value_t),
			asn_user_key_sum_7,
			asn_user_key_equal_7,
			/* format pair/arg */
			0, 0);
      am->user_ref_by_public_encrypt_key_first_8_bytes[rt]
	= hash_create2 (/* elts */ 0,
			/* user */ pointer_to_uword (am) | rt,
			/* value_bytes */ sizeof (asn_user_hash_value_t),
			asn_user_key_sum_8,
			asn_user_key_equal_8,
			/* format pair/arg */
			0, 0);
    }

  r.type_index = au->user_type_index;
  r.user_index = au->index;
  r_as_uword = asn_user_ref_as_uword (&r);

  k = 1 + 2*r_as_uword;

  hash_set (am->user_ref_by_public_encrypt_key[rt], k, r_as_uword);

  p = hash_get (am->user_ref_by_public_encrypt_key_first_7_bytes[rt], k);
  if (! p)
    {
      hv.is_inline = 1;
      hv.inline_value = r_as_uword;
      hash_set (am->user_ref_by_public_encrypt_key_first_7_bytes[rt], k, hv.as_uword);
    }
  else
    {
      hv.as_uword = p[0];
      asn_user_hash_value_update (&hv, r_as_uword);
      p[0] = hv.as_uword;
    }

  p = hash_get (am->user_ref_by_public_encrypt_key_first_8_bytes[rt], k);
  if (! p)
    {
      hv.is_inline = 1;
      hv.inline_value = r_as_uword;
      hash_set (am->user_ref_by_public_encrypt_key_first_8_bytes[rt], k, hv.as_uword);
    }
  else
    {
      hv.as_uword = p[0];
      asn_user_hash_value_update (&hv, r_as_uword);
      p[0] = hv.as_uword;
    }

  if (CLIB_DEBUG > 0)
    {
      uword i, * rv;

      rv = asn_users_matching_encrypt_key (am, rt, ck->public.encrypt_key, 7, 0);
      for (i = 0; i < vec_len (rv); i++)
        if (rv[i] == r_as_uword)
          break;
      ASSERT (i < vec_len (rv));

      rv = asn_users_matching_encrypt_key (am, rt, ck->public.encrypt_key, 8, rv);
      for (i = 0; i < vec_len (rv); i++)
        if (rv[i] == r_as_uword)
          break;
      ASSERT (i < vec_len (rv));
      vec_free (rv);
    }
}

void asn_user_update_keys (asn_main_t * am,
                           asn_rx_or_tx_t rt,
                           asn_user_t * au,
                           asn_crypto_public_keys_t * with_public_keys,
                           asn_crypto_private_keys_t * with_private_keys,
                           u32 with_random_private_keys)
{
  asn_crypto_keys_t * ck;
  asn_user_ref_t r;
  uword r_as_uword;

  r.type_index = au->user_type_index;
  r.user_index = au->index;
  r_as_uword = asn_user_ref_as_uword (&r);

  ck = &au->crypto_keys;

  if (with_public_keys)
    {
      /* With public keys implies that private keys are invalid. */
      ck->public = with_public_keys[0];
      if (with_private_keys)
	{
	  ck->private = with_private_keys[0];
	  if (CLIB_DEBUG > 0)
	    {
	      asn_crypto_create_keys (&ck->public, &ck->private, /* want_random */ 0);
	      ASSERT (! memcmp (ck->public.encrypt_key, with_public_keys->encrypt_key, sizeof (ck->public.encrypt_key)));
	      ASSERT (! memcmp (ck->public.auth_key, with_public_keys->auth_key, sizeof (ck->public.auth_key)));
	    }
	}
      else
	memset (&ck->private, ~0, sizeof (ck->private));
      au->private_key_is_valid = with_private_keys != 0;
    }
  else
    {
      /* Private keys specified? */
      if (with_private_keys)
	{
	  memcpy (&ck->private.encrypt_key, with_private_keys->encrypt_key, sizeof (ck->private.encrypt_key));
	  memcpy (&ck->private.auth_key, with_private_keys->auth_key, 32);
	  asn_crypto_create_keys (&ck->public, &ck->private, /* want_random */ 0);
	}
      else if (with_random_private_keys)
	/* Random private keys. */
	asn_crypto_create_keys (&ck->public, &ck->private, /* want_random */ 1);

      au->private_key_is_valid = (with_private_keys != 0) || with_random_private_keys;
    }

  if (! (with_public_keys || au->private_key_is_valid))
    return;

  /* If we have a private key we can and should login for this user. */
  if (au->private_key_is_valid)
    {
      asn_client_socket_t * cs;
      asn_client_socket_login_user_t * lu;
      vec_foreach (cs, am->client_sockets)
	{
          /* Make sure this user is not already a login user. */
          ASSERT (! hash_get (cs->login_user_index_by_user_ref, r_as_uword));

          vec_add2 (cs->login_users, lu, 1);
          memset (lu, 0, sizeof (lu[0]));
          lu->user_ref = r;
          hash_set (cs->login_user_index_by_user_ref, r_as_uword, lu - cs->login_users);
	}
    }

  asn_user_hash_by_public_key (am, ASN_TX, au);
}

asn_user_t *
asn_new_user_with_type (asn_main_t * am,
			asn_rx_or_tx_t rt,
			u32 user_type_index,
			asn_crypto_public_keys_t * with_public_keys,
			asn_crypto_private_keys_t * with_private_keys,
                        u32 with_random_private_keys)
{
  asn_user_t * au;
  asn_user_type_t * ut = pool_elt (asn_user_type_pool, user_type_index);
  uword * p;

  /* See if user already exists. */
  if (with_public_keys
      && pool_elts (ut->user_pool) > 0
      && (p = hash_get_mem (am->user_ref_by_public_encrypt_key[rt], with_public_keys->encrypt_key)))
    {
      au = asn_user_by_ref_as_uword (p[0]);
      ASSERT (au->user_type_index == user_type_index);
      return au;
    }
  else
    au = asn_user_alloc_with_type (ut);

  asn_user_update_keys (am, rt, au, with_public_keys, with_private_keys, with_random_private_keys);
  return au;
}

u8 * format_asn_user_mark_response (u8 * s, va_list * va)
{
  asn_user_mark_response_t * r = va_arg (*va, asn_user_mark_response_t *);
  int is_place = asn_user_mark_response_is_place (r);

  s = format (s, "user %U ", format_hex_bytes, r->user, sizeof (r->user));
  if (is_place)
    s = format (s, "place %U eta %d", format_hex_bytes, r->place, sizeof (r->place),
		asn_user_mark_response_place_eta (r));
  else
    {
      asn_position_on_earth_t pos;
      pos = asn_user_mark_response_position (r);
      s = format (s, "location lat %.9f lon %.9f", pos.latitude, pos.longitude);
    }
  return s;
}

u8 * format_asn_user_type (u8 * s, va_list * va)
{
  u32 user_type_index = va_arg (*va, u32);
  asn_user_type_t * ut = pool_elt (asn_user_type_pool, user_type_index);
  vec_add (s, ut->name, strlen (ut->name));
  return s;
}

u8 * format_asn_user (u8 * s, va_list * va)
{
  asn_user_t * au = va_arg (*va, asn_user_t *);
  
  s = format (s, "type: %U", format_asn_user_type, au->user_type_index);

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

void *
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
  h->generic_request_id.id = id;	/* remote will echo */
  return h;
}

static clib_error_t *
asn_socket_transmit_frame (asn_socket_t * as, asn_pdu_frame_t * f, uword n_user_data_bytes, uword is_last_frame)
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
  clib_error_t * error = 0;
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

static clib_error_t * asn_socket_exec_helper (asn_socket_t * as, asn_exec_ack_handler_t * ack_handler, char * fmt, va_list * va)
{
  u8 * s = va_format (0, fmt, va);
  asn_pdu_header_t * h = asn_socket_tx_add_pdu (as, ASN_PDU_exec, sizeof (h[0]) + vec_len (s));
  memcpy (h->data, s, vec_len (s));

  vec_free (s);

  {
    asn_exec_ack_handler_t ** ah;
    pool_get (as->exec_ack_handler_pool, ah);
    ah[0] = ack_handler;
    h->exec_request_id.ack_handler_index = ah - as->exec_ack_handler_pool;
  }

  return asn_socket_tx (as);
}

clib_error_t * asn_socket_exec (asn_socket_t * as, asn_exec_ack_handler_function_t * f, char * fmt, ...)
{
  asn_exec_ack_handler_t * ah = f ? asn_exec_ack_handler_create_with_function (f) : 0;
  clib_error_t * error = 0;
  va_list va;
  va_start (va, fmt);
  error = asn_socket_exec_helper (as, ah, fmt, &va);
  va_end (va);
  return error;
}

clib_error_t * asn_socket_exec_with_ack_handler (asn_socket_t * as, asn_exec_ack_handler_t * ah, char * fmt, ...)
{
  clib_error_t * error = 0;
  va_list va;
  va_start (va, fmt);
  error = asn_socket_exec_helper (as, ah, fmt, &va);
  va_end (va);
  return error;
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
  asn_pdu_id_t acked_pdu_id = ack->header.generic_request_id.id;

  switch (acked_pdu_id)
    {
    case ASN_PDU_login:
    case ASN_PDU_resume: {
      asn_user_t * au = 0;

      if (acked_pdu_id == ASN_PDU_login)
	{
	  asn_user_ref_t r;
	  asn_client_socket_t * cs;
	  asn_client_socket_login_user_t * lu;

	  r.type_index = ack->header.login_request_id.user_type_index;
	  r.user_index = ack->header.login_request_id.user_index;

	  au = asn_user_by_ref (&r);
	  if (! au)
	    return clib_error_return (0, "unknown user with type %d index %d", r.type_index, r.user_index);

	  cs = vec_elt_at_index (am->client_sockets, as->client_socket_index);
	  lu = asn_client_socket_login_user_by_ref (cs, &r);
	  if (! lu)
	    return clib_error_return (0, "unknown login user with type %d index %d", r.type_index, r.user_index);

	  if (! is_error)
	    {
	      as->session_state = ASN_SESSION_STATE_established;
	      ASSERT (! lu->is_logged_in);
	      lu->is_logged_in = 1;
	    }

	  ASSERT (lu->login_in_progress);
	  lu->login_in_progress = 0;
        }

      /* Login/resume response contains new emphemeral public key and nonce. */
      {
	struct {
	  u8 public_encrypt_key[crypto_box_public_key_bytes];
	  u8 nonce[crypto_box_nonce_bytes];
	} * rekey = (void *) ack->data;
	asn_socket_crypto_set_peer (as, rekey->public_encrypt_key, rekey->nonce);
      }

      if (au != 0 && ! is_error)
        {
          uword is_place = 0;
          /* Mark current position if valid. */
          if (au->current_marks_are_valid & (1 << is_place))
            {
              asn_position_on_earth_t pos = asn_user_mark_response_position (&au->current_marks[is_place]);
              asn_mark_position (as, pos);
            }

          /* Query marks for other users. */
          if (asn_is_user_for_ref (au, &am->self_user_ref))
            {
              error = asn_socket_exec (as, 0, "fetch%c~./asn/mark", 0);
              if (error)
                goto done;
            }
        }
      break;
    }

    case ASN_PDU_exec: {
      u32 ai = ack->header.exec_request_id.ack_handler_index;
      asn_exec_ack_handler_t * ah;

      if (pool_is_free_index (as->exec_ack_handler_pool, ai))
	{
	  error = clib_error_return (0, "unknown exec ack handler with index 0x%x", ai);
	  goto done;
	}

      ah = as->exec_ack_handler_pool[ai];
      pool_put_index (as->exec_ack_handler_pool, ai);
      if (ah)
	{
	  if (! is_error && ah->function)
	    {
	      ah->asn_main = am;
	      ah->asn_socket = as;
	      error = ah->function (ah, ack, n_bytes_in_pdu - sizeof (ack[0]));
	    }
	  clib_mem_free_in_container (ah, ah->container_offset_of_object);
	}

      return error;
    }

    default:
      ASSERT (0);
      break;
    }

 done:
  return error;
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
              format_asn_pdu_id, ack->header.generic_request_id.id,
              format_asn_ack_pdu_status, ack->status);

  if (ack->status != ASN_ACK_PDU_STATUS_success)
    s = format (s, " %*s", n_bytes - sizeof (ack[0]), ack->data);
  else if (n_bytes > sizeof (ack[0]))
    s = format (s, ", data %U", format_hex_bytes, ack->data, n_bytes - sizeof (ack[0]));

  return s;
}

static clib_error_t *
asn_socket_rx_blob_pdu (asn_main_t * am,
			asn_socket_t * as,
			asn_pdu_blob_t * blob,
			uword n_bytes_in_pdu)
{
  clib_error_t * error = 0;
  asn_blob_handler_t * bh;
  uword * p;

  vec_reset_length (am->blob_name_vector_for_reuse);
  if (blob->n_name_bytes > 0)
    vec_add (am->blob_name_vector_for_reuse, blob->name, blob->n_name_bytes);

  p = hash_get_mem (am->blob_handler_index_by_name, am->blob_name_vector_for_reuse);
  if (! p)
    {
      if (am->verbose)
	clib_warning ("no handler for blob name `%v'", am->blob_name_vector_for_reuse);
    }
  else
    {
      bh = vec_elt_at_index (am->blob_handlers, p[0]);
      error = bh->handler_function (am, as, blob, n_bytes_in_pdu);
    }

  return error;
}

static u8 * format_asn_time_stamp (u8 * s, va_list * va)
{
  u64 ts = va_arg (*va, u64);
  f64 t = clib_net_to_host_u64 (ts) * 1e-9;
  return format (s, "%U", format_time_float, "y/m/d H:M:S:F", t);
}

static u8 * format_asn_blob_pdu (u8 * s, va_list * va)
{
  asn_pdu_blob_t * blob = va_arg (*va, asn_pdu_blob_t *);
  u32 n_bytes = va_arg (*va, u32);
  u32 n_bytes_in_blob_contents = n_bytes - sizeof (blob[0]) - blob->n_name_bytes;
  uword indent = format_get_indent (s);

  s = format (s, "owner %U\n%Uauthor %U\n%Utime %U",
	      format_hex_bytes, blob->owner, sizeof (blob->owner),
              format_white_space, indent,
	      format_hex_bytes, blob->author, sizeof (blob->author),
              format_white_space, indent,
	      format_asn_time_stamp, blob->time_stamp_in_nsec_from_1970);

  if (blob->n_name_bytes > 0)
    s = format (s, "\n%Uname `%*s'",
                format_white_space, indent,
                blob->n_name_bytes, blob->name);

  if (n_bytes_in_blob_contents > 0)
    {
      s = format (s, "\n%Ucontents %U",
                  format_white_space, indent,
                  format_hex_bytes, blob->name + blob->n_name_bytes, clib_min (128, n_bytes_in_blob_contents));
      if (n_bytes_in_blob_contents > 128)
        s = format (s, "...");
    }

  return s;
}

#if 0
asn_crypto_state_t *
asn_crypto_state_for_message (asn_user_t * from_user, asn_user_t * to_user)
{
  asn_crypto_state_t * cs;

  if (clib_bitmap_get (from_user->crypto_state_by_user_index_is_valid_bitmap, to_user->index))
    return vec_elt_at_index (from_user->crypto_state_by_user_index, to_user->index);

  vec_validate (from_user->crypto_state_by_user_index, to_user->index);
  from_user->crypto_state_by_user_index_is_valid_bitmap
    = clib_bitmap_ori (from_user->crypto_state_by_user_index_is_valid_bitmap, to_user->index);

  cs = vec_elt_at_index (to_user->crypto_state_by_user_index, to_user->index);

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

  vec_add (as->rx_frame, rx_payload, n_payload_bytes);
  f = (void *) as->rx_frame;

  l = clib_net_to_host_u16 (f->n_bytes_that_follow_and_more_flag_network_byte_order);
  is_last_frame = (l & ASN_PDU_FRAME_MORE_FLAG) == 0;
  l &= ~ ASN_PDU_FRAME_MORE_FLAG;

  if (vec_len (as->rx_frame) < l + sizeof (f->n_bytes_that_follow_and_more_flag_network_byte_order))
    return 0;

  if (vec_len (as->rx_frame) > l + sizeof (f->n_bytes_that_follow_and_more_flag_network_byte_order))
    {
      error = clib_error_return (0, "frame length error frame %d websocket %d", l, n_payload_bytes);
      goto done;
    }

  n_user_data_bytes = vec_len (as->rx_frame) - STRUCT_OFFSET_OF (asn_pdu_frame_t, user_data);
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

  if (crypto_box_open_afternm (crypto_box_buffer, crypto_box_buffer, crypto_box_reserved_pad_bytes + n_user_data_bytes,
			       as->ephemeral_crypto_state.nonce[ASN_RX],
			       as->ephemeral_crypto_state.shared_secret) < 0)
    {
      error = clib_error_return (0, "authentication fails");
      goto done;
    }
  asn_crypto_increment_nonce (&as->ephemeral_crypto_state, ASN_RX, 2);

  vec_add (as->rx_pdu, crypto_box_buffer + crypto_box_reserved_pad_bytes, n_user_data_bytes);
  vec_reset_length (as->rx_frame);

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

  vec_reset_length (as->rx_pdu);

 done:
  if (error)
    {
      vec_reset_length (as->rx_pdu);
      vec_reset_length (as->rx_frame);
    }
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

      if (am->verbose)
	clib_warning ("handshake received; ephemeral sent %U", format_hex_bytes, ek->public, sizeof (ek->public));

      {
	asn_client_socket_t * cs = vec_elt_at_index (am->client_sockets, as->client_socket_index);
	cs->timestamps.first_close = 0;
      }
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

  if (as->client_socket_index < vec_len (am->client_sockets))
    {
      asn_client_socket_t * cs = &am->client_sockets[as->client_socket_index];
      int is_first_failed_close = cs->timestamps.first_close < cs->timestamps.open;
      f64 now = unix_time_now ();
      f64 backoff_min_time = 1;
      f64 backoff_max_time = 15;
      f64 backoff_expon = 1.5;

      cs->socket_index = ~0;

      if (is_first_failed_close)
	{
	  cs->timestamps.first_close = now;
	  cs->timestamps.backoff = backoff_min_time;
	}
      else
	{
	  cs->timestamps.backoff *= backoff_expon;
	  if (cs->timestamps.backoff > backoff_max_time)
	    cs->timestamps.backoff = backoff_max_time;
	}

      cs->timestamps.next_connect_attempt = now + cs->timestamps.backoff;
    }
}

clib_error_t * asn_add_connection (asn_main_t * am, u8 * socket_config, u32 client_socket_index)
{
  websocket_main_t * wsm = &am->websocket_main;
  websocket_socket_t * ws;
  asn_socket_t * as;
  clib_error_t * error = 0;

  error = websocket_client_add_connection (wsm, &ws, "ws://%s/asn/siren.ws", socket_config);
  if (error)
    return error;

  as = CONTAINER_OF (ws, asn_socket_t, websocket_socket);

  crypto_box_keypair (as->ephemeral_keys.public, as->ephemeral_keys.private, /* want_random */ 1);

  asn_socket_crypto_set_peer (as, am->server_keys.public.encrypt_key, am->server_nonce);

  {
    asn_client_socket_t * cs;
    int is_first_connection_attempt = client_socket_index == ~0;
    uword ui, ti;
    void * u;
    asn_user_type_t * ut;
    asn_user_t * au;
    asn_client_socket_login_user_t * lu;

    /* Make a copy now in case socket_config == cs->socket_config which can be freed below (*). */
    socket_config = format (0, "%s%c", socket_config, 0);

    if (client_socket_index == ~0)
      vec_add2 (am->client_sockets, cs, 1);
    else
      {
	cs = vec_elt_at_index (am->client_sockets, client_socket_index);
	asn_client_socket_free (cs); /* may be freed (*) here */
      }

    as->client_socket_index = cs - am->client_sockets;
    cs->socket_index = ws->index;
    cs->socket_config = socket_config;
    cs->socket_type = ASN_SOCKET_TYPE_websocket;
    if (is_first_connection_attempt)
      cs->timestamps.open = unix_time_now ();

    /* Add all existing users with private keys as potential login users for this connection. */
    vec_foreach_index (ti, asn_user_type_pool)
      {
        if (pool_is_free_index (asn_user_type_pool, ti))
          continue;
        ut = asn_user_type_pool[ti];
        u = ut->user_pool;
        vec_foreach_index (ui, ut->user_pool)
          {
            if (pool_is_free_index (ut->user_pool, ui))
              continue;

            au = u + ut->user_type_offset_of_asn_user;
            if (! au->private_key_is_valid)
              continue;

            {
              asn_user_ref_t r = {
                .type_index = ti,
                .user_index = ui,
              };
              uword ru = asn_user_ref_as_uword (&r);
              ASSERT (! hash_get (cs->login_user_index_by_user_ref, ru));
              vec_add2 (cs->login_users, lu, 1);
              memset (lu, 0, sizeof (lu[0]));
              lu->user_ref = r;
              hash_set (cs->login_user_index_by_user_ref, ru, lu - cs->login_users);
            }
          }

        u += ut->user_type_n_bytes;
      }

    if (am->verbose)
      {
	f64 now = unix_time_now ();
	if (is_first_connection_attempt)
	  clib_warning ("%U: trying connection to %s", format_time_float, 0, now, cs->socket_config);
	else
	  clib_warning ("%U: re-trying connection to %s, backoff %.4f",
			format_time_float, 0, now, 
			cs->socket_config, cs->timestamps.backoff);
      }
  }

  return error;
}

clib_error_t * asn_add_listener (asn_main_t * am, u8 * socket_config, int want_random_keys)
{
  websocket_main_t * wsm = &am->websocket_main;
  websocket_socket_t * ws;
  asn_socket_t * as;
  clib_error_t * error = 0;

  error = websocket_server_add_listener (wsm, (char *) socket_config, &ws);
  if (error)
    return error;

  ASSERT (want_random_keys);
  asn_crypto_create_keys (&am->server_keys.public, &am->server_keys.private, want_random_keys);

  as = CONTAINER_OF (ws, asn_socket_t, websocket_socket);
  as->client_socket_index = ~0;

  return error;
}

typedef struct {
  asn_exec_ack_handler_t ack_handler;
  u32 user_type_index;
  u32 is_self_user;
} asn_exec_newuser_ack_handler_t;

static clib_error_t *
asn_socket_exec_newuser_ack_handler (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  asn_main_t * am = ah->asn_main;
  asn_exec_newuser_ack_handler_t * nah = CONTAINER_OF (ah, asn_exec_newuser_ack_handler_t, ack_handler);
  struct {
    u8 private_encrypt_key[crypto_box_private_key_bytes];
    u8 private_auth_key[crypto_sign_private_key_bytes];
    u8 public_encrypt_key[crypto_box_public_key_bytes];
    u8 public_auth_key[crypto_sign_public_key_bytes];
  } * keys = (void *) ack->data;
  asn_crypto_keys_t ck;
  asn_user_type_t * ut = pool_elt (asn_user_type_pool, nah->user_type_index);
  asn_user_t * au;

  ASSERT (n_bytes_ack_data == sizeof (keys[0]));

  memcpy (ck.private.encrypt_key, keys->private_encrypt_key, sizeof (ck.private.encrypt_key));
  memcpy (ck.private.auth_key, keys->private_auth_key, sizeof (ck.private.auth_key));
  memcpy (ck.public.encrypt_key, keys->public_encrypt_key, sizeof (ck.public.encrypt_key));
  memcpy (ck.public.auth_key, keys->public_auth_key, sizeof (ck.public.auth_key));

  if (nah->is_self_user && am->self_user_ref.user_index != ~0)
    {
      au = asn_user_by_ref (&am->self_user_ref);
      asn_user_update_keys (am, ASN_TX, au,
			    /* with_public_keys */ &ck.public,
			    /* with_private_keys */ &ck.private,
			    /* with_random_private_keys */ 0);
    }
  else
    au = asn_new_user_with_type (am, ASN_TX, nah->user_type_index,
                                 /* with_public_keys */ &ck.public,
                                 /* with_private_keys */ &ck.private,
                                 /* with_random_private_keys */ 0);

  if (am->verbose)
    clib_warning ("newuser %stype %U, user-keys %U %U",
		  nah->is_self_user ? "self-user " : "",
		  format_asn_user_type, nah->user_type_index,
		  format_hex_bytes, au->crypto_keys.private.encrypt_key, sizeof (au->crypto_keys.private.encrypt_key),
		  format_hex_bytes, au->crypto_keys.private.auth_key, 32);

  if (nah->is_self_user)
    {
      am->self_user_ref.type_index = nah->user_type_index;
      am->self_user_ref.user_index = au->index;
    }

  if (ut->did_set_user_keys)
    ut->did_set_user_keys (au);

  return 0;
}

clib_error_t * asn_request_new_user_with_type (asn_main_t * am, asn_socket_t * as, u32 user_type_index, u32 is_self_user)
{
  asn_exec_newuser_ack_handler_t * nah = asn_exec_ack_handler_create_with_function_in_container
    (asn_socket_exec_newuser_ack_handler,
     sizeof (nah[0]),
     STRUCT_OFFSET_OF (asn_exec_newuser_ack_handler_t, ack_handler));
  nah->user_type_index = am->self_user_ref.type_index;
  nah->is_self_user = is_self_user;
  return asn_socket_exec_with_ack_handler (as, &nah->ack_handler, "newuser%c-b%c%08x", 0, 0, nah->user_type_index);
}

clib_error_t * asn_socket_login_for_user (asn_main_t * am, asn_socket_t * as, asn_user_t * au)
{
  asn_pdu_login_t * l;
  l = asn_socket_tx_add_pdu (as, ASN_PDU_login, sizeof (l[0]));
  memcpy (l->key, au->crypto_keys.public.encrypt_key, sizeof (l->key));
  memcpy (l->signature, au->crypto_keys.public.self_signed_encrypt_key, sizeof (l->signature));
  l->header.login_request_id.user_type_index = au->user_type_index;
  l->header.login_request_id.user_index = au->index;

  if (am->verbose)
    clib_warning ("type %U, key %U, sig %U",
		  format_asn_user_type, au->user_type_index,
		  format_hex_bytes, l->key, sizeof (l->key),
		  format_hex_bytes, l->signature, sizeof (l->signature));

  {
    asn_client_socket_t * cs;
    asn_client_socket_login_user_t * lu;
    asn_user_ref_t r;

    cs = vec_elt_at_index (am->client_sockets, as->client_socket_index);
    r.type_index = au->user_type_index;
    r.user_index = au->index;
    lu = asn_client_socket_login_user_by_ref (cs, &r);
    
    ASSERT (lu);
    ASSERT (! lu->login_in_progress);
    lu->login_in_progress = 1;
  }

  return asn_socket_tx (as);
}

void asn_set_blob_handler_for_name (asn_main_t * am, asn_blob_handler_function_t * handler_function, char * fmt, ...)
{
  va_list va;
  asn_blob_handler_t * bh;

  vec_add2 (am->blob_handlers, bh, 1);

  bh->handler_function = handler_function;

  va_start (va, fmt);
  bh->name = va_format (0, fmt, &va);
  va_end (va);

  if (! am->blob_handler_index_by_name)
    am->blob_handler_index_by_name = hash_create_vec (0, sizeof (bh->name[0]), sizeof (uword));

  hash_set_mem (am->blob_handler_index_by_name, bh->name, bh - am->blob_handlers);
}

clib_error_t * asn_poll_for_input (asn_main_t * am, f64 timeout)
{
  clib_error_t * error = 0;
  asn_socket_t * as;
  asn_client_socket_t * cs;
  websocket_socket_t * ws;
  f64 now;

  am->unix_file_poller.poll_for_input (&am->unix_file_poller, timeout);

  websocket_close_all_sockets_with_no_handshake (&am->websocket_main);

  now = unix_time_now ();

  /* Retry any connections that are ready. */
  vec_foreach (cs, am->client_sockets)
    {
      if (cs->socket_index == ~0)
	{
	  if (now > cs->timestamps.next_connect_attempt)
	    {
	      error = asn_add_connection (am, cs->socket_config, cs - am->client_sockets);
	      if (error)
		goto done;
	    }

	  continue;
	}

      as = asn_socket_at_index (am, cs->socket_index);
      ws = &as->websocket_socket;

      ASSERT (websocket_connection_type (ws) == WEBSOCKET_CONNECTION_TYPE_client);
      if (! ws->handshake_rx)
	continue;

      if (as->session_state != ASN_SESSION_STATE_opened)
	continue;

      if (vec_len (cs->login_users) == 0 && ! as->unknown_self_user_newuser_in_progress)
	{
	  as->unknown_self_user_newuser_in_progress = 1;
	  error = asn_request_new_user_with_type (am, as, am->self_user_ref.type_index, /* is_self_user */ 1);
	  if (error)
	    goto done;
	}
      else
	{
	  asn_client_socket_login_user_t * lu;
	  vec_foreach (lu, cs->login_users)
	    {
	      if (! lu->login_in_progress)
		{
		  asn_user_t * au = asn_user_by_ref (&lu->user_ref);
		  error = asn_socket_login_for_user (am, as, au);
		  if (error)
		    goto done;
		}
	    }
	}
    }

 done:
  return error;
}

typedef struct {
  asn_exec_ack_handler_t ack_handler;
  u8 user_encrypt_key[crypto_box_public_key_bytes];
  asn_user_mark_response_t mark_response;
} learn_user_from_auth_response_exec_ack_handler_t;

static clib_error_t * learn_user_from_auth_response_ack (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  clib_error_t * error = 0;
  struct {
    u8 auth_public_key[32];
    u8 user_type_as_u32_hex[8];
  } * ack_data = (void *) ack->data;
  asn_main_t * am = ah->asn_main;
  learn_user_from_auth_response_exec_ack_handler_t * lah = CONTAINER_OF (ah, learn_user_from_auth_response_exec_ack_handler_t, ack_handler);
  asn_user_t * au;
  asn_user_type_t * ut;
  u32 user_type_index;

  if (n_bytes_ack_data != sizeof (ack_data[0]))
    {
      error = clib_error_return (0, "expected %d bytes asn/auth + asn/user; received %d", sizeof (ack_data[0]), n_bytes_ack_data);
      goto done;
    }

  {
    int i;
    user_type_index = 0;
    for (i = 0; i < ARRAY_LEN (ack_data->user_type_as_u32_hex); i++)
      {
	u8 c = ack_data->user_type_as_u32_hex[i];
	u8 d;
	switch (c)
	  {
	  case '0' ... '9':
	    d = c - '0';
	    break;

	  case 'a' ... 'f':
	    d = 10 + (c - 'a');
	    break;

	  case 'A' ... 'F':
	    d = 10 + (c - 'A');
	    break;

	  default:
	    error = clib_error_return (0, "expected hex digit found %c", c);
	    goto done;
	  }
	user_type_index = (user_type_index << 4) | d;
      }
  }

  if (pool_is_free_index (asn_user_type_pool, user_type_index))
    {
      error = clib_error_return (0, "unknown user type %d", user_type_index);
      goto done;
    }

  if (am->verbose)
    clib_warning ("type %U, encr %U, auth %U",
		  format_asn_user_type, user_type_index,
		  format_hex_bytes, lah->user_encrypt_key, sizeof (lah->user_encrypt_key),
		  format_hex_bytes, ack_data->auth_public_key, sizeof (ack_data->auth_public_key));

  {
    asn_user_mark_response_t * mr = &lah->mark_response;
    uword is_place = asn_user_mark_response_is_place (mr);
    au = asn_update_peer_user (am, ASN_TX, user_type_index, lah->user_encrypt_key, /* auth key */ ack_data->auth_public_key);
    au->current_marks_are_valid |= 1 << is_place;
    au->current_marks[is_place] = mr[0];

    ut = pool_elt (asn_user_type_pool, user_type_index);
    if (ut->did_learn_new_user)
      ut->did_learn_new_user (au, is_place);
  }

 done:
  return error;
}

static clib_error_t * mark_blob_handler (asn_main_t * am, asn_socket_t * as, asn_pdu_blob_t * blob, u32 n_bytes_in_pdu)
{
  clib_error_t * error = 0;
  asn_user_mark_response_t * r = asn_pdu_contents_for_blob (blob);
  asn_user_t * au;
  asn_user_type_t * ut;

  if (am->verbose)
    clib_warning ("%U", format_asn_user_mark_response, r);
		
  /* If user exists just update most current mark. */
  au = asn_user_with_encrypt_key (am, ASN_TX, blob->owner);
  if (au)
    {
      uword is_place = asn_user_mark_response_is_place (r);
      au->current_marks_are_valid |= 1 << is_place;
      au->current_marks[is_place] = r[0];

      ut = pool_elt (asn_user_type_pool, au->user_type_index);

      if (ut->user_mark_did_change)
        ut->user_mark_did_change (au, is_place);

      return error;
    }

  learn_user_from_auth_response_exec_ack_handler_t * lah = asn_exec_ack_handler_create_with_function_in_container
    (learn_user_from_auth_response_ack,
     sizeof (learn_user_from_auth_response_exec_ack_handler_t),
     STRUCT_OFFSET_OF (learn_user_from_auth_response_exec_ack_handler_t, ack_handler));

  memcpy (lah->user_encrypt_key, blob->owner, sizeof (lah->user_encrypt_key));
  lah->mark_response = r[0];

  /* Ask for concatenation of user's asn/auth + asn/user. */
  return asn_socket_exec_with_ack_handler
    (as,
     &lah->ack_handler, "cat%c~%U/asn/auth%c~%U/asn/user",
     0,
     format_hex_bytes, r->user, sizeof (r->user),
     0,
     format_hex_bytes, r->user, sizeof (r->user));
}

clib_error_t * asn_mark_position (asn_socket_t * as, asn_position_on_earth_t pos)
{ return asn_socket_exec (as, 0, "mark%c%.9f%c%.9f", 0, pos.longitude, 0, pos.latitude); }

void asn_mark_position_for_all_logged_in_clients (asn_main_t * am, asn_position_on_earth_t pos)
{
  asn_client_socket_t * cs;
  asn_socket_t * as;
  clib_error_t * error = 0;

  /* Set location mark for current user. */
  {
    asn_user_t * self_user = asn_user_by_ref (&am->self_user_ref);
    uword is_place = 0;
    self_user->current_marks_are_valid |= 1 << is_place;
    self_user->current_marks[is_place] = asn_user_mark_response_for_position (pos);
  }

  /* Mark self user's position to all established sessions. */
  vec_foreach (cs, am->client_sockets)
    {
      if (cs->socket_index == ~0)
        continue;

      as = asn_socket_at_index (am, cs->socket_index);
      if (as->session_state != ASN_SESSION_STATE_established)
        continue;

      error = asn_mark_position (as, pos);
      if (error)
        clib_error_report (error);
    }
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

  asn_set_blob_handler_for_name (am, mark_blob_handler, "asn/mark");

  return error;
}

void asn_main_free (asn_main_t * am)
{
  {
    int i;
    for (i = 0; i < ARRAY_LEN (am->user_ref_by_public_encrypt_key); i++)
      {
	hash_pair_t * p;
	hash_free (am->user_ref_by_public_encrypt_key[i]);
	hash_foreach_pair (p, am->user_ref_by_public_encrypt_key_first_7_bytes[i], ({
	  asn_user_hash_value_free (p->value[0]);
	}));
	hash_free (am->user_ref_by_public_encrypt_key_first_7_bytes[i]);
	hash_foreach_pair (p, am->user_ref_by_public_encrypt_key_first_8_bytes[i], ({
	  asn_user_hash_value_free (p->value[0]);
	}));
	hash_free (am->user_ref_by_public_encrypt_key_first_8_bytes[i]);
      }
  }
  vec_free (am->blob_name_vector_for_reuse);
  {
    int i;
    vec_foreach_index (i, am->blob_handlers)
      vec_free (am->blob_handlers[i].name);
    vec_free (am->blob_handlers);
    hash_free (am->blob_handler_index_by_name);
  }
  {
    asn_client_socket_t * cs;
    vec_foreach (cs, am->client_sockets)
      asn_client_socket_free (cs);
    vec_free (am->client_sockets);
  }
}

void asn_user_type_free (asn_user_type_t * t)
{
  void * u;
  uword i;
  u = t->user_pool;
  vec_foreach_index (i, t->user_pool)
    {
      if (! pool_is_free_index (t->user_pool, i))
	{
	  asn_user_t * au = u + t->user_type_offset_of_asn_user;
	  t->free_user (au);
	  asn_user_free (au);
	}
      u += t->user_type_n_bytes;
    }
  pool_free (t->user_pool);
}

void serialize_asn_user (serialize_main_t * m, va_list * va)
{
  asn_user_t * u = va_arg (*va, asn_user_t *);

  serialize_likely_small_unsigned_integer (m, u->index);
  serialize_likely_small_unsigned_integer (m, u->private_key_is_valid);
  serialize_likely_small_unsigned_integer (m, u->current_marks_are_valid);
  serialize_likely_small_unsigned_integer (m, u->user_type_index);

  {
    asn_crypto_public_keys_t * pk = &u->crypto_keys.public;
    serialize_data (m, pk->encrypt_key, sizeof (pk->encrypt_key));
    serialize_data (m, pk->auth_key, sizeof (pk->auth_key));
    serialize_data (m, pk->self_signed_encrypt_key, sizeof (pk->self_signed_encrypt_key));
  }

  {
    int i;
    for (i = 0; i < ARRAY_LEN (u->current_marks); i++)
      {
	if (u->current_marks_are_valid & (1 << i))
	  serialize_data (m, u->current_marks[i].data_as_u8, sizeof (u->current_marks[i].data_as_u8));
      }
  }
}

void unserialize_asn_user (serialize_main_t * m, va_list * va)
{
  asn_user_t * u = va_arg (*va, asn_user_t *);

  u->index = unserialize_likely_small_unsigned_integer (m);
  u->private_key_is_valid = unserialize_likely_small_unsigned_integer (m);
  u->current_marks_are_valid = unserialize_likely_small_unsigned_integer (m);
  u->user_type_index = unserialize_likely_small_unsigned_integer (m);

  {
    asn_crypto_public_keys_t * pk = &u->crypto_keys.public;
    unserialize_data (m, pk->encrypt_key, sizeof (pk->encrypt_key));
    unserialize_data (m, pk->auth_key, sizeof (pk->auth_key));
    unserialize_data (m, pk->self_signed_encrypt_key, sizeof (pk->self_signed_encrypt_key));
  }

  {
    int i;
    for (i = 0; i < ARRAY_LEN (u->current_marks); i++)
      {
	if (u->current_marks_are_valid & (1 << i))
	  unserialize_data (m, u->current_marks[i].data_as_u8, sizeof (u->current_marks[i].data_as_u8));
      }
  }
}

void serialize_asn_user_type (serialize_main_t * m, va_list * va)
{
  CLIB_UNUSED (asn_main_t * am) = va_arg (*va, asn_main_t *);
  asn_user_type_t * t = va_arg (*va, asn_user_type_t *);
  serialize (m, serialize_pool, t->user_pool, t->user_type_n_bytes, t->serialize_pool_users);
}

void unserialize_asn_user_type (serialize_main_t * m, va_list * va)
{
  asn_main_t * am = va_arg (*va, asn_main_t *);
  asn_user_type_t * t = va_arg (*va, asn_user_type_t *);
  unserialize (m, unserialize_pool, &t->user_pool, t->user_type_n_bytes, t->unserialize_pool_users);

  {
    void * u;
    uword i;
    u = t->user_pool;
    vec_foreach_index (i, t->user_pool)
      {
        if (! pool_is_free_index (t->user_pool, i))
          {
            asn_user_t * au = u + t->user_type_offset_of_asn_user;
            asn_user_hash_by_public_key (am, ASN_TX, au);
          }
        u += t->user_type_n_bytes;
      }
  }
}

void serialize_asn_main (serialize_main_t * m, va_list * va)
{
  asn_main_t * am = va_arg (*va, asn_main_t *);
  serialize_integer (m, am->self_user_ref.user_index, sizeof (u32));
}

void unserialize_asn_main (serialize_main_t * m, va_list * va)
{
  asn_main_t * am = va_arg (*va, asn_main_t *);
  unserialize_integer (m, &am->self_user_ref.user_index, sizeof (u32));
}
