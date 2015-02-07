#include <uclib/uclib.h>
#include <casn/asn.h>

typedef struct {
  asn_socket_t asn_socket;

  f64 last_echo_time;
} test_asn_socket_t;

typedef struct {
  asn_user_t asn_user;
} test_asn_user_t;

typedef struct {
  asn_main_t asn_main;
  
  u8 * client_config;
  u8 * server_config;

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

  f64 time_interval_between_echos;

  asn_user_type_t user_types[1];
} test_asn_main_t;

static clib_error_t * asn_socket_exec_echo_data_ack_handler (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  if (n_bytes_ack_data > 1)
    clib_warning ("%*s", n_bytes_ack_data - (ack->data[n_bytes_ack_data - 1] == '\n'), ack->data);
  return 0;
}

static clib_error_t * unnamed_blob_handler (asn_main_t * am, asn_socket_t * as, asn_pdu_blob_t * blob, u32 n_bytes_in_pdu)
{
  if (am->verbose)
    clib_warning ("%*s", asn_pdu_n_content_bytes_for_blob (blob, n_bytes_in_pdu), asn_pdu_contents_for_blob (blob));
  return 0;
}

int test_asn_main (unformat_input_t * input)
{
  test_asn_main_t _tm, * tm = &_tm;
  asn_main_t * am = &tm->asn_main;
  websocket_main_t * wsm = &am->websocket_main;
  clib_error_t * error = 0;

#if 0
  if (0) {
    u8 cipher[32+32], nonce[24], key[32];

    memset (nonce, 0, sizeof (nonce));
    memset (cipher, 0, sizeof (cipher));
    memset (key, 0, sizeof (key));

    crypto_secretbox (cipher, cipher, sizeof (cipher), nonce, key);
    clib_warning ("%U", format_hex_bytes, cipher, sizeof (cipher));
    if (crypto_secretbox_open (cipher, cipher, sizeof (cipher), nonce, key) < 0)
      os_panic ();
    clib_warning ("%U", format_hex_bytes, cipher, sizeof (cipher));
  }
#endif

  memset (tm, 0, sizeof (tm[0]));
  am->server_config = (u8 *) "localhost:5000";
  wsm->verbose = 0;
  am->verbose = 0;
  tm->n_clients = 1;
  tm->time_interval_between_echos = 1 /* sec */;

  tm->user_types[0].name = "actual";
  tm->user_types[0].user_type_n_bytes = sizeof (test_asn_user_t);
  tm->user_types[0].user_type_offset_of_asn_user = STRUCT_OFFSET_OF (test_asn_user_t, asn_user);
  asn_register_user_type (&tm->user_types[0]);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "listen %s", &am->server_config))
        ;
      else if (unformat (input, "connect %s", &tm->client_config))
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
      else if (unformat (input, "dt %f", &tm->time_interval_between_echos))
	;
      else
        {
          clib_warning ("unknown input `%U'", format_unformat_error, input);
          return 1;
        }
    }

  if (! tm->client_config)
    tm->client_config = tm->server_config;

  if (! tm->client_config)
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
  am->self_user_ref.user_index = ~0;
  am->self_user_ref.type_index = tm->user_types[0].index;
  if (tm->user_keys.private_encrypt_key)
    {
      asn_crypto_private_keys_t pk;
      asn_user_t * au;
      memcpy (pk.encrypt_key, tm->user_keys.private_encrypt_key, vec_len (tm->user_keys.private_encrypt_key));
      memcpy (pk.auth_key, tm->user_keys.private_auth_key, vec_len (tm->user_keys.private_auth_key));
      au = asn_new_user_with_type (am, ASN_TX, am->self_user_ref.type_index,
                                   /* with_public_keys */ 0,
                                   /* with_private_keys */ &pk,
                                   /* with_random_private_keys */ 0);
      am->self_user_ref.user_index = au->index;
    }

  /* Unnamed "message" blobs. */
  asn_set_blob_handler_for_name (am, unnamed_blob_handler, "");

  {
    int i;

    for (i = 0; i < tm->n_clients; i++)
      {
        error = asn_add_connection (am, tm->client_config, /* client_socket_index */ ~0);
        if (error)
          goto done;
      }
  }

  clib_mem_trace (0);

  while (1)
    {
      test_asn_socket_t * tas;
      asn_socket_t * as;
      asn_client_socket_t * cs;
      f64 now;

      error = asn_poll_for_input (am, 10e-3);
      if (error)
	clib_error_report (error);

      now = unix_time_now ();

      vec_foreach (cs, am->client_sockets)
	{
	  test_asn_socket_t * as_pool = am->websocket_main.user_socket_pool;

	  if (cs->socket_index == ~0)
	    continue;

	  tas = pool_elt_at_index (as_pool, cs->socket_index);
	  as = &tas->asn_socket;

	  if (as->session_state == ASN_SESSION_STATE_established
	      && now - tas->last_echo_time > tm->time_interval_between_echos)
	    {
	      if (0) {
		error = asn_socket_exec (as, asn_socket_exec_echo_data_ack_handler, "echo%cfoo", 0);
		if (error)
		  clib_error_report (error);
	      }

	      if (1) {
                asn_position_on_earth_t pos = {
                  .latitude = 37.1234567,
                  .longitude = -122.89012345,
                };
		error = asn_mark_position (as, pos);
		if (error)
		  clib_error_report (error);
	      }

	      if (1) {
		uword ui;
		asn_user_t * user_pool = asn_user_pool_for_user_ref (&am->self_user_ref);
		vec_foreach_index (ui, user_pool)
		  {
		    asn_user_t * au = user_pool +  ui;
		    if (! pool_is_free_index (user_pool, ui) && ui != am->self_user_ref.user_index)
		      {
			static int oingoes;
			error = asn_socket_exec (as, 0, "blob%c~%U%c-%c%chello %d",
                                                 0,
                                                 format_hex_bytes, au->crypto_keys.public.encrypt_key, 8,
                                                 0, 0, 0,
                                                 oingoes++);
			if (error)
			  clib_error_report (error);
		      }
		  }
	      }

	      if (am->verbose)
		clib_warning ("%U", format_clib_mem_usage, /* verbose */ 0);

	      if (tas->last_echo_time == 0)
		tas->last_echo_time = now;
	      else
		tas->last_echo_time += tm->time_interval_between_echos;
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
