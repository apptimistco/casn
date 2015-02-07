#ifndef included_asn_app_h
#define included_asn_app_h

#include <uclib/uclib.h>
#include <casn/asn.h>

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
} asn_app_location_t;

always_inline void asn_app_location_free (asn_app_location_t * l)
{
  vec_free (l->unique_id);
  uword i;
  vec_foreach_index (i, l->address_lines) vec_free (l->address_lines[i]);
  vec_free (l->address_lines);
  vec_free (l->thumbnail_as_image_data);
}

#define foreach_asn_app_message_type		\
  _ (text)					\
  _ (photo)					\
  _ (video)					\
  _ (user_group_add_del_request)		\
  _ (friend_request)

typedef enum {
#define _(f) ASN_APP_MESSAGE_TYPE_##f,
  foreach_asn_app_message_type
#undef _
} asn_app_message_type_t;

typedef struct {
  u32 from_user_index;
  asn_app_message_type_t type;
  f64 time_stamp;
} asn_app_message_header_t;

typedef struct {
  asn_app_message_header_t header;
  u8 * text;
} asn_app_text_message_t;

always_inline void asn_app_text_message_free (asn_app_text_message_t * m)
{ vec_free (m->text); }

typedef struct {
  asn_app_message_header_t header;
  asn_app_photo_t photo;
} asn_app_photo_message_t;

always_inline void asn_app_photo_message_free (asn_app_photo_message_t * p)
{ asn_app_photo_free (&p->photo); }

typedef asn_app_photo_message_t asn_app_video_message_t;

always_inline void asn_app_video_message_free (asn_app_video_message_t * p)
{ asn_app_photo_free (&p->photo); }

typedef struct {
  asn_app_message_header_t header;
} asn_app_friend_request_message_t;

always_inline void asn_app_friend_request_message_free (asn_app_friend_request_message_t * m)
{ }

typedef struct {
  asn_app_message_header_t header;
  asn_user_id_t group_id;
  asn_user_id_t user_to_add;
  /* Zero for add; non-zero for delete. */
  u8 is_del;
} asn_app_user_group_add_del_request_message_t;

always_inline void asn_app_user_group_add_del_request_message_free (asn_app_user_group_add_del_request_message_t * m)
{ }

typedef union {
  asn_app_message_header_t header;
#define _(f) asn_app_##f##_message_t f;
  foreach_asn_app_message_type
#undef _
} asn_app_message_union_t;

always_inline void asn_app_message_union_free (asn_app_message_union_t * m)
{
  switch (m->header.type) {
#define _(f) case ASN_APP_MESSAGE_TYPE_##f: asn_app_##f##_message_free (&m->f); break;
    foreach_asn_app_message_type;
#undef _
  }
}

always_inline void asn_app_message_union_vector_free (asn_app_message_union_t ** mv)
{
  asn_app_message_union_t * m;
  vec_foreach (m, *mv)
    asn_app_message_union_free (m);
  vec_free (*mv);
}

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

  asn_app_message_union_t * messages_by_increasing_time;
} asn_app_gen_user_t;

always_inline void asn_app_gen_user_set_position (asn_app_gen_user_t * u, asn_position_on_earth_t pos)
{
  uword is_place = 0;
  u->asn_user.current_marks[is_place] = asn_user_mark_response_for_position (pos);
  u->asn_user.current_marks_are_valid = 1 << is_place;
}

always_inline void asn_app_gen_user_free (asn_app_gen_user_t * u)
{
  asn_user_free (&u->asn_user);

  {
    asn_app_photo_t * p;
    vec_foreach (p, u->photos)
      asn_app_photo_free (p);
    vec_free (u->photos);
  }

  asn_app_message_union_vector_free (&u->messages_by_increasing_time);
}

typedef struct {
  asn_app_gen_user_t gen_user;
  u32 show_user_on_map : 1;
  u32 is_checked_in : 1;
  uword * user_friends;
  u32 recent_check_in_location_index;
  asn_app_location_t recent_check_in_locations[32];
  uword * events_rsvpd_for_user;
} asn_app_user_t;

always_inline asn_app_location_t *
asn_app_check_in_location_for_user (asn_app_user_t * au)
{
  return (au->is_checked_in
          ? (au->recent_check_in_locations
             + ((au->recent_check_in_location_index - 1) % ARRAY_LEN (au->recent_check_in_locations)))
          : 0);
}

always_inline void asn_app_user_free (asn_app_user_t * u)
{
  asn_app_gen_user_free (&u->gen_user);

  {
    int i;
    for (i = 0; i < ARRAY_LEN (u->recent_check_in_locations); i++)
      asn_app_location_free (&u->recent_check_in_locations[i]);
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

  /* Event is created by current user. */
  u32 is_created_by_self_user : 1;

  /* Location of event. */
  asn_app_location_t location;

  /* Hash of user indices that have RSVPd for this event. */
  uword * users_rsvpd_for_event;
} asn_app_event_t;

always_inline void asn_app_event_free (asn_app_event_t * e)
{
  asn_app_gen_user_free (&e->gen_user);
  asn_app_location_free (&e->location);
  hash_free (e->users_rsvpd_for_event);
}

typedef struct {
  asn_app_attribute_t * attributes;
  u32 * attribute_map_for_unserialize;
  uword * attribute_by_name;
} asn_app_attribute_main_t;

typedef struct {
  asn_user_type_t user_type;

  asn_app_attribute_main_t attribute_main;

  void (* did_update_user_profile) (asn_user_t * au);
} asn_app_user_type_t;

#define foreach_asn_app_user_type		\
  _ (user) _ (user_group) _ (event) _ (place)

typedef enum {
#define _(f) ASN_APP_USER_TYPE_##f,
  foreach_asn_app_user_type
#undef _
  ASN_APP_N_USER_TYPE,
} asn_app_user_type_enum_t;

typedef struct {
  asn_main_t asn_main;

  asn_app_user_type_t user_types[ASN_APP_N_USER_TYPE];
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

always_inline asn_app_event_t *
asn_app_event_with_index (asn_app_main_t * am, u32 index)
{
  asn_app_event_t * us = am->user_types[ASN_APP_USER_TYPE_event].user_type.user_pool;
  return pool_elt_at_index (us, index);
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

void asn_app_main_init (asn_app_main_t * am);
void asn_app_main_free (asn_app_main_t * am);

clib_error_t * asn_app_main_write_to_file (asn_app_main_t * am, char * unix_file);
clib_error_t * asn_app_main_read_from_file (asn_app_main_t * am, char * unix_file);

u32 asn_app_add_attribute (asn_app_attribute_main_t * am, asn_app_attribute_type_t type, char * fmt, ...);
u32 asn_app_add_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, char * fmt, ...);

void * asn_app_get_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui);
void asn_app_set_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui, ...);

void asn_app_set_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui, char * fmt, ...);
u8 * asn_app_get_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui);
uword * asn_app_get_oneof_attribute_multiple_choice_bitmap (asn_app_attribute_main_t * am, u32 ai, u32 ui, uword * r);

int asn_app_sort_message_by_increasing_time (asn_app_message_union_t * m0, asn_app_message_union_t * m1);

serialize_function_t serialize_asn_app_main, unserialize_asn_app_main;
serialize_function_t serialize_asn_app_profile_for_user, unserialize_asn_app_profile_for_user;

#endif /* included_asn_app_h */
