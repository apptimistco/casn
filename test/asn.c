#include <uclib/uclib.h>
#include <casn/asn.h>

typedef struct {
  asn_socket_t asn_socket;

  f64 last_echo_time;
} test_asn_socket_t;

typedef struct {
  asn_main_t asn_main;
  
  struct {
    u8 * public_encrypt_key;
    u8 * public_auth_key;
    u8 * nonce;
  } server_keys;

  struct {
    u8 * private_encrypt_key;
    u8 * private_auth_key;
  } user_keys;

  u32 n_clients;
} test_asn_main_t;

static clib_error_t * asn_socket_exec_cat_blob_ack_handler (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  if (n_bytes_ack_data > 0)
    clib_warning ("%*s", n_bytes_ack_data, ack->data);
  else
    clib_warning ("empty");
  return 0;
}

static clib_error_t * asn_socket_exec_echo_data_ack_handler (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  if (n_bytes_ack_data > 1)
    clib_warning ("%*s", n_bytes_ack_data - (ack->data[n_bytes_ack_data - 1] == '\n'), ack->data);
  return 0;
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
} asn_mark_response_t;

always_inline uword
asn_mark_response_is_place (asn_mark_response_t * r)
{ return (r->place_and_eta & 0xf0) == 0x70; }

always_inline uword
asn_mark_response_place_eta (asn_mark_response_t * r)
{
  ASSERT (asn_mark_response_is_place (r));
  return r->place_and_eta & 0xf;
}

static u8 * format_asn_mark_response (u8 * s, va_list * va)
{
  asn_mark_response_t * r = va_arg (*va, asn_mark_response_t *);
  int is_place = asn_mark_response_is_place (r);

  s = format (s, "user %U ", format_hex_bytes, r->user, sizeof (r->user));
  if (is_place)
    s = format (s, "place %U eta %d", format_hex_bytes, r->place, sizeof (r->place),
		asn_mark_response_place_eta (r));
  else
    s = format (s, "location %.9f %.9f",
		1e-6 * clib_net_to_host_i32 (r->longitude_mul_1e6),
		1e-6 * clib_net_to_host_i32 (r->latitude_mul_1e6));
  return s;
}

asn_user_t *
asn_update_peer_user (asn_main_t * am, asn_rx_or_tx_t rt, asn_user_type_t user_type,
		      u8 * encrypt_key, u8 * auth_key)
{
  asn_user_t * au = asn_user_with_encrypt_key (am, rt, encrypt_key);
  if (! au)
    {
      asn_crypto_public_keys_t pk;
      memcpy (pk.encrypt_key, encrypt_key, sizeof (pk.encrypt_key));
      memcpy (pk.auth_key, auth_key, sizeof (pk.auth_key));
      au = asn_new_user_with_type (am, rt, user_type, &pk, /* private keys */ 0);
    }

  ASSERT (au->user_type == user_type);
  if (auth_key)
    memcpy (au->crypto_keys.public.auth_key, auth_key, sizeof (au->crypto_keys.public.auth_key));

  return au;
}

typedef struct {
  asn_exec_ack_handler_t ack_handler;
  u8 user_encrypt_key[crypto_box_public_key_bytes];
} learn_user_from_auth_response_exec_ack_handler_t;

static clib_error_t * learn_user_from_auth_response_ack (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  asn_main_t * am = ah->asn_main;
  learn_user_from_auth_response_exec_ack_handler_t * lah = CONTAINER_OF (ah, learn_user_from_auth_response_exec_ack_handler_t, ack_handler);

  if (n_bytes_ack_data != crypto_sign_public_key_bytes)
    return clib_error_return (0, "expected 32 bytes asn/auth; received %d", n_bytes_ack_data);

  if (am->verbose)
    clib_warning ("encr %U auth %U",
		  format_hex_bytes, lah->user_encrypt_key, sizeof (lah->user_encrypt_key),
		  format_hex_bytes, ack->data, n_bytes_ack_data);

  asn_update_peer_user (am, ASN_TX, ASN_USER_TYPE_actual, lah->user_encrypt_key, /* auth key */ ack->data);

  return 0;
}

static clib_error_t * mark_blob_handler (asn_main_t * am, asn_socket_t * as, asn_pdu_blob_t * blob, u32 n_bytes_in_pdu)
{
  asn_mark_response_t * r = asn_pdu_contents_for_blob (blob);

  if (am->verbose)
    clib_warning ("%U", format_asn_mark_response, r);
		
  learn_user_from_auth_response_exec_ack_handler_t * lah = asn_exec_ack_handler_create_with_function_in_container
    (learn_user_from_auth_response_ack,
     sizeof (learn_user_from_auth_response_exec_ack_handler_t),
     STRUCT_OFFSET_OF (learn_user_from_auth_response_exec_ack_handler_t, ack_handler));

  memcpy (lah->user_encrypt_key, blob->owner, sizeof (lah->user_encrypt_key));

  return asn_exec_with_ack_handler (as, &lah->ack_handler, "cat%c~%U/asn/auth", 0, format_hex_bytes, r->user, sizeof (r->user));
}

static clib_error_t * asn_mark_position (asn_socket_t * as, f64 longitude, f64 latitude)
{ return asn_exec (as, 0, "mark%c%.9f%c%.9f", 0, longitude, 0, latitude); }

static clib_error_t * unnamed_blob_handler (asn_main_t * am, asn_socket_t * as, asn_pdu_blob_t * blob, u32 n_bytes_in_pdu)
{
  clib_warning ("%*s", asn_pdu_n_content_bytes_for_blob (blob, n_bytes_in_pdu), asn_pdu_contents_for_blob (blob));
  return 0;
}

int test_asn_main (unformat_input_t * input)
{
  test_asn_main_t _tm, * tm = &_tm;
  asn_main_t * am = &tm->asn_main;
  websocket_main_t * wsm = &am->websocket_main;
  clib_error_t * error = 0;

  memset (tm, 0, sizeof (tm[0]));
  am->server_config = (u8 *) "localhost:5000";
  wsm->verbose = 0;
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
      else if (unformat (input, "user-keys %U %U",
			 unformat_hex_string, &tm->user_keys.private_encrypt_key,
			 unformat_hex_string, &tm->user_keys.private_auth_key))
	{
	  if (vec_len (tm->user_keys.private_encrypt_key) != 32)
	    clib_error ("user encrypt not %d bytes", 32);
	  if (vec_len (tm->user_keys.private_auth_key) != 32)
	    clib_error ("user auth key not %d bytes", 32);
	}
      else if (unformat (input, "server-keys %U %U %U",
			 unformat_hex_string, &tm->server_keys.public_encrypt_key,
			 unformat_hex_string, &tm->server_keys.public_auth_key,
			 unformat_hex_string, &tm->server_keys.nonce))
	{
	  if (vec_len (tm->server_keys.public_encrypt_key) != sizeof (am->server_keys.public.encrypt_key))
	    clib_error ("server encrypt not %d bytes", sizeof (am->server_keys.public.encrypt_key));
	  if (vec_len (tm->server_keys.public_auth_key) != 32)
	    clib_error ("server auth key not %d bytes", 32);
	  if (vec_len (tm->server_keys.nonce) != crypto_box_nonce_bytes)
	    clib_error ("server nonce not %d bytes", crypto_box_nonce_bytes);
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

  if (! am->client_config)
    am->client_config = am->server_config;

  if (! am->client_config)
    clib_error ("must specify either server-config or client-config");

  error = asn_main_init (am, sizeof (test_asn_socket_t), STRUCT_OFFSET_OF (test_asn_socket_t, asn_socket));
  if (error)
    goto done;

  if (vec_len (tm->server_keys.public_encrypt_key) > 0)
    {
      asn_crypto_public_keys_t * k = &am->server_keys.public;

      memset (&am->server_keys.private, ~0, sizeof (am->server_keys.private));
      memcpy (k->encrypt_key, tm->server_keys.public_encrypt_key, sizeof (k->encrypt_key));
      memcpy (k->auth_key, tm->server_keys.public_auth_key, sizeof (k->auth_key));
      memcpy (am->server_nonce, tm->server_keys.nonce, sizeof (am->server_nonce));

      memset (tm->server_keys.public_encrypt_key, 0, vec_len (tm->server_keys.public_encrypt_key));
      memset (tm->server_keys.public_auth_key, 0, vec_len (tm->server_keys.public_auth_key));
      memset (tm->server_keys.nonce, 0, vec_len (tm->server_keys.nonce));

      vec_free (tm->server_keys.public_encrypt_key);
      vec_free (tm->server_keys.public_auth_key);
      vec_free (tm->server_keys.nonce);
    }

  if (am->server_config)
    {
      error = asn_add_listener (am, am->server_config, /* want_random_keys */ 1);
      if (error)
	goto done;
    }

  /* Possibly create self user. */
  am->self_user_index = ~0;
  if (tm->user_keys.private_encrypt_key)
    {
      asn_crypto_private_keys_t pk;
      asn_user_t * au;
      memcpy (pk.encrypt_key, tm->user_keys.private_encrypt_key, vec_len (tm->user_keys.private_encrypt_key));
      memcpy (pk.auth_key, tm->user_keys.private_auth_key, vec_len (tm->user_keys.private_auth_key));
      au = asn_new_user_with_type (am, ASN_TX, ASN_USER_TYPE_actual, /* with_public_keys */ 0, &pk);
      am->self_user_index = au->index;
    }

  {
    int i;

    for (i = 0; i < tm->n_clients; i++)
      {
        error = asn_add_connection (am, am->client_config);
        if (error)
          goto done;
      }

    asn_set_blob_handler_for_name (am, mark_blob_handler, "asn/mark");
    asn_set_blob_handler_for_name (am, unnamed_blob_handler, "");

    while (pool_elts (am->websocket_main.user_socket_pool) > (am->server_config ? 1 : 0))
      {
        am->unix_file_poller.poll_for_input (&am->unix_file_poller, /* timeout */ 10e-3);

	test_asn_socket_t * as_pool = am->websocket_main.user_socket_pool;
        test_asn_socket_t * tas;
	asn_socket_t * as;
	websocket_socket_t * ws;
        f64 now;
	uword i;

	websocket_close_all_sockets_with_no_handshake (wsm);

        now = unix_time_now ();

	vec_foreach_index (i, as_pool)
	  {
	    if (pool_is_free_index (as_pool, i))
	      continue;
	    tas = pool_elt_at_index (as_pool, i);
	    as = &tas->asn_socket;
	    ws = &as->websocket_socket;

	    if (websocket_connection_type (ws) == WEBSOCKET_CONNECTION_TYPE_client
		&& ws->handshake_rx)
	      {
		switch (as->session_state)
		  {
		  case ASN_SESSION_STATE_opened:
		    error = asn_login_for_self_user (am, as);
		    if (error)
		      clib_error_report (error);
		    break;

		  case ASN_SESSION_STATE_established: {
		    f64 dt = 1;
		    if (now - tas->last_echo_time > dt)
		      {
			if (0) {
			  error = asn_exec (as, asn_socket_exec_echo_data_ack_handler, "echo%cfoo", 0);
			  if (error)
			    clib_error_report (error);
			}

			if (1) {
			  error = asn_mark_position (as, -37.1234567, 122.89012345);
			  if (error)
			    clib_error_report (error);
			}

			if (1) {
			  uword ui;
			  asn_user_t * user_pool = am->known_users[ASN_TX].user_pool;
			  vec_foreach_index (ui, user_pool)
			    {
			      asn_user_t * au = user_pool + ui;
			      if (! pool_is_free_index (user_pool, ui) && ui != am->self_user_index)
				{
				  static int oingoes;
				  error = asn_exec (as, 0, "blob%c~%U%c-%c%chello %d",
						    0,
						    format_hex_bytes, au->crypto_keys.public.encrypt_key, 8,
						    0, 0, 0,
						    oingoes++);
				  if (error)
				    clib_error_report (error);
				}
			    }
			}

			if (tas->last_echo_time == 0)
			  tas->last_echo_time = now;
			else
			  tas->last_echo_time += dt;
		      }

		    if (0) {
		      clib_error_t * error;
		      error = asn_exec (as, asn_socket_exec_echo_data_ack_handler, "blob%cfart%c-%c%ccontents of fart",
					0, 0, 0, 0);
		      if (error)
			clib_error_report (error);
		    }

		    if (0) {
		      clib_error_t * error;
		      error = asn_exec (as, asn_socket_exec_cat_blob_ack_handler, "cat%cfart", 0);
		      if (error)
			clib_error_report (error);
		    }

		    break;
		  }

		  default:
		    break;
		  }
	      }
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
