#ifndef included_asn_app_h
#define included_asn_app_h

#include <uclib/uclib.h>
#include <casn/asn.h>

struct asn_app_main_t;

typedef struct {
  /* Thumbnail for object as JPEG (or other) image. */
  u8 * thumbnail_as_image_data;

  /* Blob name which holds raw data for image, video etc. */
  u8 * blob_name_for_raw_data;
} asn_app_photo_t;

always_inline void asn_app_photo_free (asn_app_photo_t * p)
{
  vec_free (p->thumbnail_as_image_data);
  vec_free (p->blob_name_for_raw_data);
}

typedef struct {
  u8 * unique_id;		/* => name of location blob */
  u8 ** address_lines;
  u8 * thumbnail_as_image_data;
  asn_position_on_earth_t position_on_earth;
} asn_app_location_t;

always_inline void asn_app_location_free (asn_app_location_t * l)
{
  uword i;
  vec_free (l->unique_id);
  vec_foreach_index (i, l->address_lines) vec_free (l->address_lines[i]);
  vec_free (l->address_lines);
  vec_free (l->thumbnail_as_image_data);
}

always_inline void asn_app_location_dup (asn_app_location_t * dst, asn_app_location_t * l)
{
  uword i;
  memset (dst, 0, sizeof (dst[0]));
  dst->unique_id = vec_dup (l->unique_id);
  vec_resize (dst->address_lines, vec_len (l->address_lines));
  vec_foreach_index (i, l->address_lines) dst->address_lines[i] = vec_dup (l->address_lines[i]);
  dst->thumbnail_as_image_data = vec_dup (l->thumbnail_as_image_data);
}

typedef struct {
  u32 type_index;
  u32 pool_index;
} asn_app_message_ref_t;

typedef struct {
  asn_app_message_ref_t ref;
  u32 from_user_index;
  u64 time_stamp_in_nsec_from_1970;
} asn_app_message_header_t;

typedef struct {
  char * name;
  u32 index;
  u32 was_registered;

  u32 user_msg_n_bytes;
  u32 user_msg_offset_of_message_header;
  serialize_function_t * serialize, * unserialize;

  void (* did_receive_message) (struct asn_app_main_t * am, asn_user_t * au, asn_app_message_header_t * msg);

  clib_error_t * (* maybe_learn_new_user_from_message) (asn_main_t * am, asn_socket_t * as, asn_user_t * au,
                                                        asn_app_message_header_t * h,
                                                        uword * learning_new_user_from_message);

  void (* free) (asn_app_message_header_t * h);
} asn_app_message_type_t;

CLIB_INIT_ADD_TYPE (asn_app_message_type_t);

always_inline uword
asn_app_message_has_type (asn_app_message_header_t * h, asn_app_message_type_t * t)
{
  ASSERT (t->was_registered);
  return h->ref.type_index == t->index;
}

asn_app_message_type_t ** asn_app_message_type_pool;
uword * asn_app_message_type_pool_index_by_name;

always_inline asn_app_message_type_t *
asn_app_message_type_by_name (char * name)
{
  uword * p = hash_get_mem (asn_app_message_type_pool_index_by_name, name);
  return p ? pool_elt (asn_app_message_type_pool, p[0]) : 0;
}

uword asn_app_register_message_type (asn_app_message_type_t * t);

typedef struct {
  void ** message_pool_by_type;
  mhash_t message_ref_by_time_stamp;
  asn_app_message_header_t most_recent_msg_header;
  u32 * user_pairs;
} asn_app_user_messages_t;

void asn_app_user_messages_free (asn_app_user_messages_t * m);

always_inline uword
asn_app_user_messages_is_empty (asn_app_user_messages_t * m)
{ return m->most_recent_msg_header.time_stamp_in_nsec_from_1970 == 0; }

always_inline void *
asn_app_message_header_for_ref_helper (asn_app_user_messages_t * um, asn_app_message_ref_t * ref,
                                       uword want_header)
{
  void * pool = vec_elt (um->message_pool_by_type, ref->type_index);
  asn_app_message_type_t * mt = pool_elt (asn_app_message_type_pool, ref->type_index);
  return (pool
          + ref->pool_index * mt->user_msg_n_bytes
          + (want_header ? mt->user_msg_offset_of_message_header : 0));
}

always_inline asn_app_message_header_t *
asn_app_message_header_for_ref (asn_app_user_messages_t * um, asn_app_message_ref_t * ref)
{ return asn_app_message_header_for_ref_helper (um, ref, /* want_header */ 1); }

always_inline void *
asn_app_message_for_ref (asn_app_user_messages_t * um, asn_app_message_ref_t * ref)
{ return asn_app_message_header_for_ref_helper (um, ref, /* want_header */ 0); }

always_inline void *
asn_app_new_message_with_type (asn_app_user_messages_t * um, asn_app_message_type_t * mt)
{
  void * pool, * msg;
  asn_app_message_header_t * h;
  uword index;
  ASSERT (mt->was_registered);
  ASSERT (mt == pool_elt (asn_app_message_type_pool, mt->index));
  vec_validate (um->message_pool_by_type, mt->index);
  pool = vec_elt (um->message_pool_by_type, mt->index);
  pool = pool_get_free_index (pool, mt->user_msg_n_bytes, &index);
  um->message_pool_by_type[mt->index] = pool;
  msg = pool + index * mt->user_msg_n_bytes;
  memset (msg, 0, mt->user_msg_n_bytes);
  h = msg + mt->user_msg_offset_of_message_header;
  h->ref.pool_index = index;
  h->ref.type_index = mt->index;
  return msg;
}

always_inline void
asn_app_free_message_with_type (asn_app_user_messages_t * um, asn_app_message_type_t * mt,
                                void * msg)
{
  asn_app_message_header_t * h = msg - mt->user_msg_offset_of_message_header;
  void * pool;
  pool = vec_elt (um->message_pool_by_type, mt->index);
  ASSERT (! pool_is_free_index (pool, h->ref.pool_index));
  if (mt->free)
    mt->free (h);
  pool_put_index (pool, h->ref.pool_index);
}

typedef union {
  struct {
    u8 src[crypto_box_public_key_bytes];
    u8 dst[crypto_box_public_key_bytes];
  };
  uword as_uword[2 * crypto_box_public_key_bytes / sizeof (uword)];
} asn_app_message_public_key_pair_t;

typedef struct {
  asn_app_message_public_key_pair_t public_key_pair;

  /* Random ephemeral private key to use for this destination or source. */
  union {
    u8 src_private_key[crypto_box_private_key_bytes];
    u8 dst_private_key[crypto_box_private_key_bytes];
  };

  /* src -> dst shared secret. */
  u8 shared_secret[crypto_box_shared_secret_bytes];

  /* src public -> owner private shared secret. */
  u8 nonce[crypto_box_nonce_bytes];

  u32 index;
} asn_app_message_user_pair_t;

#define foreach_asn_app_attribute_type		\
  _ (u8) _ (u16) _ (u32) _ (u64) _ (f64)	\
  _ (bitmap)					\
  _ (string)					\
  _ (oneof_single_choice)			\
  _ (oneof_multiple_choice)

typedef enum {
#define _(f) ASN_APP_ATTRIBUTE_TYPE_##f,
  foreach_asn_app_attribute_type
#undef _
} asn_app_attribute_type_t;

typedef struct {
  asn_app_attribute_type_t type;

  u32 index;

  /* Attribute name. */
  u8 * name;

  /* For oneof types hash table mapping value string to index. */
  uword * oneof_index_by_value;

  u8 ** oneof_values;

  asn_app_attribute_type_t oneof_value_type_for_unserialize;
  u32 * oneof_map_for_unserialize;

  uword * value_is_valid_bitmap;

  union {
    u8 * as_u8;
    u16 * as_u16;
    u32 * as_u32;
    u64 * as_u64;
    uword ** as_bitmap;
    f64 * as_f64;
    u8 ** as_string;
  } values;
} asn_app_attribute_t;

always_inline uword
asn_app_attribute_is_oneof (asn_app_attribute_t * a)
{
  return (a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice
          || a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_multiple_choice);
}

typedef struct {
  asn_user_t asn_user;

  /* Photos of user, event, user group. */
  asn_app_photo_t * photos;

  asn_app_user_messages_t user_messages;
} asn_app_gen_user_t;

always_inline void asn_app_gen_user_set_position (asn_app_gen_user_t * u, asn_position_on_earth_t pos)
{
  uword is_place = 0;
  u->asn_user.current_marks[is_place] = asn_user_mark_response_for_position (pos);
  u->asn_user.current_marks_are_valid = 1 << is_place;
}

always_inline void asn_app_gen_user_free (asn_app_gen_user_t * u)
{
  {
    asn_app_photo_t * p;
    vec_foreach (p, u->photos)
      asn_app_photo_free (p);
    vec_free (u->photos);
  }

  asn_app_user_messages_free (&u->user_messages);
}

typedef struct {
  asn_user_key_t user_key;
  u64 time_stamp_in_nsec_from_1970;
  u8 * message;
} asn_app_user_check_in_at_place_t;

always_inline void asn_app_user_check_in_at_place_free (asn_app_user_check_in_at_place_t * c)
{ vec_free (c->message); }

typedef struct {
  asn_app_gen_user_t gen_user;
  uword * user_friends;
  uword * events_rsvpd_for_user;
  asn_app_user_check_in_at_place_t * check_ins;
} asn_app_user_t;

always_inline uword
asn_app_user_check_in_at_place_vector_is_sorted (asn_app_user_check_in_at_place_t * cis)
{
  uword i, is_sorted = 1;
  if (vec_len (cis) >= 2)
    {
      for (i = 0; i < vec_len (cis) - 1; i++)
        {
          is_sorted &= cis[i].time_stamp_in_nsec_from_1970 < cis[i+1].time_stamp_in_nsec_from_1970;
          ASSERT (is_sorted);
        }
    }
  return is_sorted;
}

always_inline asn_app_user_check_in_at_place_t *
asn_app_last_check_in_location_for_user (asn_app_user_t * au)
{
  ASSERT (asn_app_user_check_in_at_place_vector_is_sorted (au->check_ins));
  return au->check_ins ? vec_end (au->check_ins) - 1 : 0;
}

always_inline void asn_app_user_free (asn_app_user_t * u)
{
  asn_app_gen_user_free (&u->gen_user);

  {
    asn_app_user_check_in_at_place_t * ci;
    vec_foreach (ci, u->check_ins)
      asn_app_user_check_in_at_place_free (ci);
    vec_free (u->check_ins);
  }

  hash_free (u->user_friends);
  hash_free (u->events_rsvpd_for_user);
}

typedef struct {
  asn_app_gen_user_t gen_user;

  /* Hash of user indices that are in this group. */
  uword * group_users;
} asn_app_user_group_t;

always_inline void asn_app_user_group_free (asn_app_user_group_t * u)
{
  asn_app_gen_user_free (&u->gen_user);
  hash_free (u->group_users);
}

typedef struct {
  asn_app_gen_user_t gen_user;

  /* Private versus public event. */
  u32 is_private : 1;

  /* Location of event. */
  asn_app_location_t location;

  /* Hash of user indices that have RSVPd for this event. */
  uword * users_rsvpd_for_event;

  /* Hash of user/group indices that have been invited to this event. */
  uword * users_invited_to_event;
  uword * groups_invited_to_event;
} asn_app_event_t;

always_inline void asn_app_event_free (asn_app_event_t * e)
{
  asn_app_gen_user_free (&e->gen_user);
  asn_app_location_free (&e->location);
  hash_free (e->users_rsvpd_for_event);
  hash_free (e->users_invited_to_event);
  hash_free (e->groups_invited_to_event);
}

typedef struct {
  asn_app_gen_user_t gen_user;
  asn_app_location_t location;
  asn_app_user_check_in_at_place_t * recent_check_ins_at_place;
} asn_app_place_t;

typedef struct {
  asn_app_attribute_t * attributes;
  u32 * attribute_map_for_unserialize;
  uword * attribute_by_name;
} asn_app_attribute_main_t;

typedef struct {
  asn_user_type_t user_type;

  asn_app_attribute_main_t attribute_main;

  serialize_function_t * serialize_blob_contents, * unserialize_blob_contents;

  void (* free_user) (asn_user_t * au);

  void (* did_update_user) (asn_user_t * au, u32 is_new_user);

  void (* did_receive_message) (asn_user_t * au, asn_app_message_header_t * msg);

  void (* update_subscribers) (asn_main_t * am,
                               asn_user_t * au,
                               asn_blob_type_t * blob_type,
                               asn_user_ref_t * subcriber_user_refs,
                               u32 n_subscriber_user_refs);
} asn_app_user_type_t;

always_inline asn_app_user_type_t *
asn_app_user_type_for_user (asn_user_t * au)
{
  asn_user_type_t * ut = asn_user_type_for_user (au);
  return CONTAINER_OF (ut, asn_app_user_type_t, user_type);
}

#define foreach_asn_app_user_type		\
  _ (user) _ (user_group) _ (event) _ (place)

typedef enum {
#define _(f) ASN_APP_USER_TYPE_##f,
  foreach_asn_app_user_type
#undef _
  ASN_APP_N_USER_TYPE,
} asn_app_user_type_enum_t;

typedef struct asn_app_main_t {
  asn_main_t asn_main;

  asn_app_user_type_t user_types[ASN_APP_N_USER_TYPE];

  uword * place_index_by_unique_id;

  asn_app_message_user_pair_t * user_message_pair_pool;

  /* Hash mapping crypto header to message user key pair. */
  uword * user_message_pair_index_by_public_key_pair;
} asn_app_main_t;

always_inline asn_app_user_t *
asn_app_user_with_index (asn_app_main_t * am, u32 index)
{
  asn_app_user_t * us = am->user_types[ASN_APP_USER_TYPE_user].user_type.user_pool;
  return pool_elt_at_index (us, index);
}

always_inline asn_app_user_group_t *
asn_app_user_group_with_index (asn_app_main_t * am, u32 index)
{
  asn_app_user_group_t * us = am->user_types[ASN_APP_USER_TYPE_user_group].user_type.user_pool;
  return pool_elt_at_index (us, index);
}

always_inline clib_error_t *
asn_app_user_group_save_users (asn_app_main_t * am, asn_app_user_group_t * g)
{
    return asn_save_users (&am->asn_main, /* socket */ 0, &g->gen_user.asn_user,
                           "asn/subscribers", am->user_types[ASN_APP_USER_TYPE_user].user_type.index,
                           g->group_users);
}

always_inline asn_app_event_t *
asn_app_event_with_index (asn_app_main_t * am, u32 index)
{
  asn_app_event_t * us = am->user_types[ASN_APP_USER_TYPE_event].user_type.user_pool;
  return pool_elt_at_index (us, index);
}

always_inline asn_app_place_t *
asn_app_place_with_index (asn_app_main_t * am, u32 index)
{
  asn_app_place_t * ps = am->user_types[ASN_APP_USER_TYPE_place].user_type.user_pool;
  return pool_elt_at_index (ps, index);
}

always_inline asn_app_place_t *
asn_app_place_with_unique_id (asn_app_main_t * am, u8 * unique_id)
{
  uword * p = hash_get_mem (am->place_index_by_unique_id, unique_id);
  return p ? asn_app_place_with_index (am, p[0]) : 0;
}

always_inline asn_app_place_t *
asn_app_place_with_key (asn_app_main_t * am, u8 * encrypt_key)
{
  asn_user_t * au = asn_user_with_encrypt_key (&am->asn_main, ASN_TX, encrypt_key);
  return au ? CONTAINER_OF (au, asn_app_place_t, gen_user.asn_user) : 0;
}

always_inline void
asn_app_place_set_unique_id (asn_app_main_t * am, asn_app_place_t * p)
{
  if (! am->place_index_by_unique_id)
        am->place_index_by_unique_id = hash_create_vec (0, sizeof (p->location.unique_id[0]), sizeof (uword));
  hash_set_mem (am->place_index_by_unique_id, p->location.unique_id, p->gen_user.asn_user.index);
}

always_inline void *
asn_app_new_user_with_type (asn_app_main_t * am, asn_app_user_type_enum_t t)
{
  asn_user_type_t * ut = &am->user_types[t].user_type;
  asn_user_t * au = asn_new_user_with_type (&am->asn_main, ASN_TX, ut->index,
					    /* with_public_keys */ 0,
					    /* with_private_keys */ 0,
                                            /* with_random_private_keys */ 0);
  return (void *) au - ut->user_type_offset_of_asn_user;
}

always_inline uword * asn_app_users_add1 (uword * users, uword user_index)
{
  if (! users)
    users = hash_create (sizeof (uword), /* value bytes */ 0);
  hash_set1 (users, user_index);
  return users;
}

always_inline uword * asn_app_users_del1 (uword * users, uword user_index)
{
  hash_unset (users, user_index);
  return users;
}

always_inline uword * asn_app_users_add_hash (uword * users, uword * user_hash)
{
    hash_pair_t * p;
    hash_foreach_pair (p, user_hash, ({
          users = asn_app_users_add1 (users, p->key);
    }));
    return users;
}

always_inline uword * asn_app_users_add_group (asn_app_main_t * am, uword * users, uword group_index)
{
    asn_app_user_group_t * g = asn_app_user_group_with_index (am, group_index);
    return asn_app_users_add_hash (users, g->group_users);
}

always_inline void asn_app_users_free (uword * users) { hash_free (users); }

void asn_app_main_init (asn_app_main_t * am);
void asn_app_main_free (asn_app_main_t * am);

void asn_app_free_user_with_type (asn_app_main_t * am, asn_app_user_type_enum_t user_type, u32 user_index);
clib_error_t * asn_app_create_user_and_blob_with_type (asn_app_main_t * am, asn_app_user_type_enum_t user_type, u32 user_index);

clib_error_t * asn_app_main_write_to_file (asn_app_main_t * am, char * unix_file);
clib_error_t * asn_app_main_read_from_file (asn_app_main_t * am, char * unix_file);

u32 asn_app_add_attribute (asn_app_attribute_main_t * am, asn_app_attribute_type_t type, char * fmt, ...);
u32 asn_app_add_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, char * fmt, ...);

void * asn_app_get_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui);
void asn_app_set_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui, ...);

void asn_app_invalidate_attribute (asn_app_attribute_main_t * am, u32 ai, u32 i);
void asn_app_invalidate_all_attributes (asn_app_attribute_main_t * am, u32 i);

always_inline void asn_app_validate_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui)
{
  asn_app_attribute_t * a = vec_elt_at_index (am->attributes, ai);
  a->value_is_valid_bitmap = clib_bitmap_ori (a->value_is_valid_bitmap, ui);
}

void asn_app_set_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui, char * fmt, ...);
u8 * asn_app_get_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui);
uword * asn_app_get_oneof_attribute_multiple_choice_bitmap (asn_app_attribute_main_t * am, u32 ai, u32 ui, uword * r);

clib_error_t * asn_app_user_update_blob (asn_app_main_t * app_main, asn_app_user_type_enum_t user_type, u32 user_index);

clib_error_t * asn_app_save_subscribers_for_event (asn_app_main_t * am, asn_socket_t * as, u32 user_index);

asn_blob_type_t asn_app_messages_blob_type, asn_app_user_blob_type, asn_app_subscribers_blob_type,
  asn_app_user_friends_blob_type, asn_app_events_rsvpd_for_user_blob_type, asn_app_event_users_invited_blob_type,
  asn_app_event_groups_invited_blob_type, asn_app_users_rsvpd_for_event_blob_type, asn_app_check_in_blob_type;

serialize_function_t serialize_asn_app_main, unserialize_asn_app_main;

typedef struct {
  asn_app_message_header_t header;
  u8 * text;
} asn_app_text_message_t;

always_inline void asn_app_text_message_free (asn_app_text_message_t * m)
{ vec_free (m->text); }

asn_app_message_type_t asn_app_text_message_type;

clib_error_t *
asn_app_send_text_message_to_user (asn_app_main_t * app_main,
                                   asn_app_user_type_enum_t to_user_type,
                                   u32 to_user_index,
                                   char * fmt, ...);

#define foreach_asn_app_invitation_type         \
  _ (invalid)                                   \
  _ (invitation_offer)                          \
  _ (accept_invitation)                         \
  _ (decline_invitation)

typedef enum {
#define _(f) ASN_APP_INVITATION_TYPE_##f,
  foreach_asn_app_invitation_type
#undef _
} asn_app_invitation_type_t;

typedef struct {
  asn_app_message_header_t header;
  asn_app_invitation_type_t type;
  /* Key for user, group or event that invitation is for. */
  asn_user_key_t invitation_for_key;
} asn_app_invitation_message_t;

asn_app_message_type_t asn_app_invitation_message_type;

clib_error_t *
asn_app_send_invitation_message_to_user (asn_app_main_t * app_main,
                                         asn_app_user_type_enum_t invitation_user_type,
                                         u32 invitation_user_index,
                                         asn_app_user_type_enum_t to_user_type,
                                         u32 to_user_index,
                                         asn_app_invitation_type_t invitation_type);

clib_error_t * asn_app_find_existing_place_with_location (asn_app_main_t * am, asn_app_location_t * location);
clib_error_t * asn_app_check_in_at_location (asn_app_main_t * am, asn_app_location_t * location, u8 * check_in_message);

#endif /* included_asn_app_h */
