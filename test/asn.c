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

static clib_error_t * asn_socket_exec_cat_blob_ack_handler (asn_main_t * am, asn_socket_t * as, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  if (n_bytes_ack_data > 0)
    clib_warning ("%*s", n_bytes_ack_data, ack->data);
  else
    clib_warning ("empty");
  return 0;
}

static clib_error_t * asn_socket_exec_echo_data_ack_handler (asn_main_t * am, asn_socket_t * as, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  if (n_bytes_ack_data > 1)
    clib_warning ("%*s", n_bytes_ack_data - (ack->data[n_bytes_ack_data - 1] == '\n'), ack->data);
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
      memcpy (pk.encrypt_key, tm->user_keys.private_encrypt_key, vec_len (tm->user_keys.private_encrypt_key));
      memcpy (pk.auth_key, tm->user_keys.private_auth_key, vec_len (tm->user_keys.private_auth_key));
      am->self_user_index = asn_main_new_user_with_type (am, ASN_TX, ASN_USER_TYPE_actual, /* with_public_keys */ 0, &pk);
    }

  {
    int i;

    for (i = 0; i < tm->n_clients; i++)
      {
        error = asn_add_connection (am, am->client_config);
        if (error)
          goto done;
      }

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

			error = asn_exec (as, asn_socket_exec_echo_data_ack_handler, "mark%c37.7833%c122.4167", 0, 0);
			if (error)
			  clib_error_report (error);

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
