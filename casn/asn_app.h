#ifndef included_asn_app_h
#define included_asn_app_h

#include <uclib/uclib.h>

/* ASN blobs are named by their 64 byte SHA-512 sum. */
typedef struct {
  u8 sum[64];
} asn_blob_id_t;

typedef struct {
  u8 public_key[32];
} asn_user_id_t;

typedef struct {
  /* Service key for public blobs; otherwise user's public key. */
  asn_user_id_t user;

  asn_blob_id_t blob;
} asn_user_blob_t;

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
  u8 * thumbnail_as_jpeg_data;
  asn_blob_id_t asn_id_of_raw_data;
} asn_app_photo_message_t;

always_inline void asn_app_photo_message_free (asn_app_photo_message_t * p)
{ vec_free (p->thumbnail_as_jpeg_data); }

typedef asn_app_photo_message_t asn_app_video_message_t;

always_inline void asn_app_video_message_free (asn_app_video_message_t * p)
{ vec_free (p->thumbnail_as_jpeg_data); }

typedef struct {
  asn_app_message_header_t header;
} asn_app_friend_request_message_t;

always_inline void asn_app_friend_request_message_free (asn_app_friend_request_message_t * m)
{ }

typedef struct {
  asn_app_message_header_t header;
  asn_user_id_t group_owner;
  asn_user_blob_t user_to_add;
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

typedef struct {
  u8 * thumbnail_as_image_data;
  u8 * blob_name_for_raw_image_data;
} asn_app_photo_t;

always_inline void asn_app_photo_free (asn_app_photo_t * p)
{ vec_free (p->thumbnail_as_image_data); vec_free (p->blob_name_for_raw_image_data); }

typedef struct {
  f64 longitude, latitude;
} asn_app_position_on_earth_t;

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

typedef struct {
  u32 index;
  u32 is_private : 1;
  u32 is_checked_in : 1;
  uword * user_friends;
  asn_app_photo_t * photos;
  u32 recent_check_in_location_index;
  asn_app_location_t recent_check_in_locations[32];
  asn_app_position_on_earth_t position_on_earth;
  asn_app_message_union_t * messages_by_increasing_time;
  uword * events_rsvpd_for_user;
} asn_app_user_t;

always_inline void asn_app_user_free (asn_app_user_t * u)
{
  {
    asn_app_photo_t * p;
    vec_foreach (p, u->photos)
      asn_app_photo_free (p);
    vec_free (u->photos);
  }

  {
    int i;
    for (i = 0; i < ARRAY_LEN (u->recent_check_in_locations); i++)
      asn_app_location_free (&u->recent_check_in_locations[i]);
  }

  asn_app_message_union_vector_free (&u->messages_by_increasing_time);

  hash_free (u->user_friends);
  hash_free (u->events_rsvpd_for_user);
}

typedef struct {
  u32 index;

  asn_app_photo_t * photos;

  /* Hash of user indices that are in this group. */
  uword * group_users;

  asn_app_message_union_t * messages_by_increasing_time;
} asn_app_user_group_t;

always_inline void asn_app_user_group_free (asn_app_user_group_t * u)
{
  {
    asn_app_photo_t * p;
    vec_foreach (p, u->photos)
      asn_app_photo_free (p);
    vec_free (u->photos);
  }

  hash_free (u->group_users);

  asn_app_message_union_vector_free (&u->messages_by_increasing_time);
}

typedef struct {
  u32 index;

  /* Private versus public event. */
  u32 is_private : 1;

  /* Event is created by current user. */
  u32 is_created_by_self_user : 1;

  /* Location of event. */
  asn_app_location_t location;

  asn_app_position_on_earth_t position_on_earth;

  asn_app_photo_t * photos;

  /* Hash of user indices that have RSVPd for this event. */
  uword * users_rsvpd_for_event;
  
  /* Comments about this event. */
  asn_app_message_union_t * messages_by_increasing_time;
} asn_app_event_t;

always_inline void asn_app_event_free (asn_app_event_t * e)
{
  asn_app_location_free (&e->location);
  {
    asn_app_photo_t * p;
    vec_foreach (p, e->photos)
      asn_app_photo_free (p);
    vec_free (e->photos);
  }
  hash_free (e->users_rsvpd_for_event);
  asn_app_message_union_vector_free (&e->messages_by_increasing_time);
}

typedef struct {
  asn_app_attribute_t * attributes;
  u32 * attribute_map_for_unserialize;
  uword * attribute_by_name;
} asn_app_attribute_main_t;

typedef struct {
  asn_app_user_t * user_pool;
  uword * user_index_by_id;
  u32 self_user_index;
  asn_app_attribute_main_t user_attribute_main;

  asn_app_user_group_t * user_group_pool;
  uword * user_group_index_by_id;
  asn_app_attribute_main_t user_group_attribute_main;

  asn_app_event_t * event_pool;
  uword * event_index_by_id;
  asn_app_attribute_main_t event_attribute_main;
} asn_app_main_t;

void asn_app_main_free (asn_app_main_t * am);
clib_error_t * asn_app_main_write_to_file (asn_app_main_t * am, char * unix_file);
clib_error_t * asn_app_main_read_from_file (asn_app_main_t * am, char * unix_file);

u32 asn_app_add_attribute (asn_app_attribute_main_t * am, asn_app_attribute_type_t type, char * fmt, ...);
u32 asn_app_add_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, char * fmt, ...);

void * asn_app_get_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui);
void asn_app_set_attribute (asn_app_attribute_t * a, u32 i, ...);
void asn_app_set_oneof_attribute (asn_app_attribute_t * a, u32 i, char * fmt, ...);

int asn_app_sort_message_by_increasing_time (asn_app_message_union_t * m0, asn_app_message_union_t * m1);

serialize_function_t serialize_asn_app_main, unserialize_asn_app_main;

#endif /* included_asn_app_h */
