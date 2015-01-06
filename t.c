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

#ifndef included_asn_app_h
#define included_asn_app_h

#endif /* included_asn_app_h */

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
  u8 * thumbnail_as_jpeg_data;
  asn_blob_id_t id_for_raw_data;
} asn_app_photo_t;

always_inline void asn_app_photo_free (asn_app_photo_t * p)
{ vec_free (p->thumbnail_as_jpeg_data); }

static void
serialize_asn_app_photo (serialize_main_t * m, va_list * va)
{
  asn_app_photo_t * p = va_arg (*va, asn_app_photo_t *);
  vec_serialize (m, p->thumbnail_as_jpeg_data, serialize_vec_8);
}

static void
unserialize_asn_app_photo (serialize_main_t * m, va_list * va)
{
  asn_app_photo_t * p = va_arg (*va, asn_app_photo_t *);
  vec_unserialize (m, &p->thumbnail_as_jpeg_data, unserialize_vec_8);
}

typedef struct {
  f64 longitude, latitude;
} asn_app_position_on_earth_t;

typedef struct {
  u8 * unique_id;		/* => name of location blob */
  u8 ** address_lines;
  u8 * thumbnail_as_jpeg_data;
  asn_app_position_on_earth_t position;
} asn_app_location_t;

always_inline void asn_app_location_free (asn_app_location_t * l)
{
  vec_free (l->unique_id);
  uword i;
  vec_foreach_index (i, l->address_lines) vec_free (l->address_lines[i]);
  vec_free (l->address_lines);
  vec_free (l->thumbnail_as_jpeg_data);
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

always_inline asn_app_attribute_type_t
asn_app_attribute_value_type (asn_app_attribute_t * pa)
{
  asn_app_attribute_type_t type = pa->type;
  if (type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice)
    {
      u32 n_values = hash_elts (pa->oneof_index_by_value);
      if (n_values < (1 << BITS (u8)))
	type = ASN_APP_ATTRIBUTE_TYPE_u8;
      else if (n_values < (1 << BITS (u16)))
	type = ASN_APP_ATTRIBUTE_TYPE_u16;
      else
	type = ASN_APP_ATTRIBUTE_TYPE_u32;
    }
  else if (type == ASN_APP_ATTRIBUTE_TYPE_oneof_multiple_choice)
    {
      u32 n_values = hash_elts (pa->oneof_index_by_value);
      if (n_values <= BITS (u8))
	type = ASN_APP_ATTRIBUTE_TYPE_u8;
      else if (n_values <= BITS (u16))
	type = ASN_APP_ATTRIBUTE_TYPE_u16;
      else if (n_values <= BITS (u32))
	type = ASN_APP_ATTRIBUTE_TYPE_u32;
      else if (n_values <= BITS (u64))
	type = ASN_APP_ATTRIBUTE_TYPE_u64;
      else
	type = ASN_APP_ATTRIBUTE_TYPE_bitmap;
    }
  return type;
}

always_inline void asn_app_attribute_free (asn_app_attribute_t * a)
{
  uword i;
  asn_app_attribute_type_t value_type = asn_app_attribute_value_type (a);
  switch (value_type)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
    case ASN_APP_ATTRIBUTE_TYPE_u16:
    case ASN_APP_ATTRIBUTE_TYPE_u32:
    case ASN_APP_ATTRIBUTE_TYPE_u64:
    case ASN_APP_ATTRIBUTE_TYPE_f64:
      vec_free (a->values.as_u8);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_string:
      vec_foreach_index (i, a->values.as_string)
	vec_free (a->values.as_string[i]);
      vec_free (a->values.as_string);
      break;
    default:
      ASSERT (0);
      break;
    }
  vec_foreach_index (i, a->oneof_values) vec_free (a->oneof_values[i]);
  vec_free (a->oneof_values);
  hash_free (a->oneof_index_by_value);
  vec_free (a->name);
}

static void
serialize_asn_app_attribute_value (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_t * a = va_arg (*va, asn_app_attribute_t *);
  u32 i = va_arg (*va, u32);
  asn_app_attribute_type_t value_type = asn_app_attribute_value_type (a);

  switch (value_type)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
      vec_validate (a->values.as_u8, i);
      serialize_integer (m, a->values.as_u8[i], sizeof (u8));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u16:
      vec_validate (a->values.as_u16, i);
      serialize_integer (m, a->values.as_u16[i], sizeof (u16));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u32:
      vec_validate (a->values.as_u32, i);
      serialize_integer (m, a->values.as_u32[i], sizeof (u32));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u64:
      vec_validate (a->values.as_u64, i);
      serialize_integer (m, a->values.as_u64[i], sizeof (u64));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_f64:
      vec_validate (a->values.as_f64, i);
      serialize (m, serialize_f64, a->values.as_f64[i]);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_string:
      vec_validate (a->values.as_string, i);
      vec_serialize (m, a->values.as_string[i], serialize_vec_8);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_bitmap:
      vec_validate (a->values.as_bitmap, i);
      serialize_bitmap (m, a->values.as_bitmap[i]);
      break;
    default:
      ASSERT (0);
      break;
    }
}

static void
unserialize_asn_app_attribute_value (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_t * a = va_arg (*va, asn_app_attribute_t *);
  u32 i = va_arg (*va, u32);
  asn_app_attribute_type_t value_type = asn_app_attribute_value_type (a);
  switch (value_type)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
      vec_validate (a->values.as_u8, i);
      unserialize_integer (m, &a->values.as_u8[i], sizeof (u8));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u16:
      vec_validate (a->values.as_u16, i);
      unserialize_integer (m, &a->values.as_u16[i], sizeof (u16));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u32:
      vec_validate (a->values.as_u32, i);
      unserialize_integer (m, &a->values.as_u32[i], sizeof (u32));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u64:
      vec_validate (a->values.as_u64, i);
      unserialize_integer (m, &a->values.as_u64[i], sizeof (u64));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_f64:
      vec_validate (a->values.as_f64, i);
      unserialize (m, unserialize_f64, &a->values.as_f64[i]);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_string:
      vec_validate (a->values.as_string, i);
      vec_unserialize (m, &a->values.as_string[i], unserialize_vec_8);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_bitmap:
      vec_validate (a->values.as_bitmap, i);
      a->values.as_bitmap[i] = unserialize_bitmap (m);
      break;
    default:
      ASSERT (0);
      break;
    }
}

typedef struct {
  u32 index;
  uword * user_friends;
  asn_app_photo_t * photos;
  asn_app_location_t location_of_current_check_in;
  asn_app_message_union_t * messages_by_increasing_time;
} asn_app_user_t;

always_inline void asn_app_user_free (asn_app_user_t * u)
{
  {
    asn_app_photo_t * p;
    vec_foreach (p, u->photos)
      asn_app_photo_free (p);
    vec_free (u->photos);
  }

  asn_app_location_free (&u->location_of_current_check_in);

  asn_app_message_union_vector_free (&u->messages_by_increasing_time);

  hash_free (u->user_friends);
}

static void
serialize_asn_app_user (serialize_main_t * m, va_list * va)
{
  asn_app_user_t * u = va_arg (*va, asn_app_user_t *);
  u32 n_user = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_user; i++)
    vec_serialize (m, u[i].photos, serialize_asn_app_photo);
}

static void
unserialize_asn_app_user (serialize_main_t * m, va_list * va)
{
  asn_app_user_t * u = va_arg (*va, asn_app_user_t *);
  u32 n_user = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_user; i++)
    vec_unserialize (m, &u[i].photos, unserialize_asn_app_photo);
}

typedef struct {
  /* Group name and description. */
  u8 * name;
  
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
  /* Start/end times in minutes from epoch. */
  u32 lo_in_minutes_from_epoch;
  u32 hi_in_minutes_from_epoch;
} asn_app_time_range_t;

typedef struct {
  u8 * name;
  u8 * description;

  asn_app_location_t location;

  asn_app_location_t time;

  asn_app_photo_t * photos;

  /* Hash of user indices that have RSVPd for this event. */
  uword * rsvps;
  
  asn_app_message_union_t * messages_by_increasing_time;
} asn_app_event_t;

always_inline void asn_app_event_free (asn_app_event_t * e)
{
  vec_free (e->name);
  vec_free (e->description);
  asn_app_location_free (&e->location);
  {
    asn_app_photo_t * p;
    vec_foreach (p, e->photos)
      asn_app_photo_free (p);
    vec_free (e->photos);
  }
  hash_free (e->rsvps);
  asn_app_message_union_vector_free (&e->messages_by_increasing_time);
}

typedef struct {
  asn_app_user_t * user_pool;
  asn_app_attribute_t * user_attributes;
  u32 * user_attribute_map_for_unserialize;
  uword * user_attribute_by_name;
  uword * user_index_by_id;

  asn_app_user_group_t * user_group_pool;
  uword * user_group_index_by_id;

  asn_app_event_t * event_pool;
  uword * event_index_by_id;
} asn_app_main_t;

void asn_app_main_free (asn_app_main_t * am)
{
  {
    asn_app_user_t * u;
    asn_app_attribute_t * a;
    pool_foreach (u, am->user_pool, ({ asn_app_user_free (u); }));
    pool_free (am->user_pool);
    vec_foreach (a, am->user_attributes) asn_app_attribute_free (a);
    vec_free (am->user_attributes);
    hash_free (am->user_attribute_by_name);
    vec_free (am->user_attribute_map_for_unserialize);
  }

  {
    asn_app_user_group_t * u;
    pool_foreach (u, am->user_group_pool, ({ asn_app_user_group_free (u); }));
    pool_free (am->user_group_pool);
  }

  {
    asn_app_event_t * e;
    pool_foreach (e, am->event_pool, ({ asn_app_event_free (e); }));
    pool_free (am->event_pool);
  }

  hash_free (am->user_index_by_id);
  hash_free (am->user_group_index_by_id);
  hash_free (am->event_index_by_id);
}

static void
serialize_asn_app_attributes_for_user (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  u32 ui = va_arg (*va, u32);
  asn_app_attribute_t * a;
  vec_foreach (a, am->user_attributes)
    serialize (m, serialize_asn_app_attribute_value, a, ui);
}

static void
unserialize_asn_app_attributes_for_user (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  u32 ui = va_arg (*va, u32);
  u32 i;
  asn_app_attribute_t * a;
  for (i = 0; i < vec_len (am->user_attribute_map_for_unserialize); i++)
    {
      a = vec_elt_at_index (am->user_attributes, am->user_attribute_map_for_unserialize[i]);
      unserialize (m, unserialize_asn_app_attribute_value, a, ui);
    }
}

static char * asn_app_main_serialize_magic = "asn_app_main v0";

void
serialize_asn_app_main (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);

  serialize_magic (m, asn_app_main_serialize_magic, strlen (asn_app_main_serialize_magic));

  {
    asn_app_attribute_t * a;
    serialize_likely_small_unsigned_integer (m, vec_len (am->user_attributes));
    vec_foreach (a, am->user_attributes)
      vec_serialize (m, a->name, serialize_vec_8);
  }

  pool_serialize (m, am->user_pool, serialize_asn_app_user);

  {
    asn_app_user_t * u;
    pool_foreach (u, am->user_pool, ({ serialize (m, serialize_asn_app_attributes_for_user, am, u->index); }));
  }
}

void
unserialize_asn_app_main (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);

  unserialize_check_magic (m, asn_app_main_serialize_magic,
			   strlen (asn_app_main_serialize_magic),
			   "asn_app_main");

  {
    asn_app_attribute_t * a;
    u32 n_attrs = unserialize_likely_small_unsigned_integer (m);
    u32 i;
    vec_resize (am->user_attribute_map_for_unserialize, n_attrs);
    for (i = 0; i < n_attrs; i++)
      {
	u8 * name;
	uword * p;
	vec_unserialize (m, &name, unserialize_vec_8);
	if (! (p = hash_get_mem (am->user_attribute_by_name, name)))
	  serialize_error_return (m, "unknown attribute named `%v'", name);
	vec_free (name);
	a = vec_elt_at_index (am->user_attributes, *p);
	am->user_attribute_map_for_unserialize[i] = a->index;
      }
  }

  pool_unserialize (m, &am->user_pool, unserialize_asn_app_user);

  {
    asn_app_user_t * u;
    pool_foreach (u, am->user_pool, ({ unserialize (m, unserialize_asn_app_attributes_for_user, am, u->index); }));
    vec_free (am->user_attribute_map_for_unserialize);
  }
}

void * asn_app_get_attribute (asn_app_attribute_t * pa, u32 ui)
{
  asn_app_attribute_type_t type = asn_app_attribute_value_type (pa);

  switch (type)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
      vec_validate (pa->values.as_u8, ui);
      return pa->values.as_u8 + ui;

    case ASN_APP_ATTRIBUTE_TYPE_u16:
      vec_validate (pa->values.as_u16, ui);
      return pa->values.as_u16 + ui;

    case ASN_APP_ATTRIBUTE_TYPE_u32:
      vec_validate (pa->values.as_u32, ui);
      return pa->values.as_u32 + ui;

    case ASN_APP_ATTRIBUTE_TYPE_u64:
      vec_validate (pa->values.as_u64, ui);
      return pa->values.as_u64 + ui;

    case ASN_APP_ATTRIBUTE_TYPE_f64:
      vec_validate (pa->values.as_f64, ui);
      return pa->values.as_f64 + ui;

    case ASN_APP_ATTRIBUTE_TYPE_string:
      vec_validate (pa->values.as_string, ui);
      return pa->values.as_string + ui;

    case ASN_APP_ATTRIBUTE_TYPE_bitmap:
      vec_validate (pa->values.as_bitmap, ui);
      return pa->values.as_bitmap + ui;

    default:
      ASSERT (0);
      return 0;
    }
}

void * asn_app_get_user_attribute (asn_app_main_t * am, u32 ai, u32 ui)
{
  asn_app_attribute_t * pa = vec_elt_at_index (am->user_attributes, ai);
  return asn_app_get_attribute (pa, ui);
}

always_inline void
asn_app_set_attribute (asn_app_attribute_t * a, u32 i, ...)
{
  va_list va;
  va_start (va, i);
  asn_app_attribute_type_t value_type = asn_app_attribute_value_type (a);
  switch (value_type)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
      vec_validate (a->values.as_u8, i);
      a->values.as_u8[i] = va_arg (va, u32);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u16:
      vec_validate (a->values.as_u16, i);
      a->values.as_u16[i] = va_arg (va, u32);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u32:
      vec_validate (a->values.as_u32, i);
      a->values.as_u32[i] = va_arg (va, u32);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u64:
      vec_validate (a->values.as_u64, i);
      a->values.as_u64[i] = va_arg (va, u64);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_bitmap:
      vec_validate (a->values.as_bitmap, i);
      a->values.as_bitmap[i] = clib_bitmap_ori (a->values.as_bitmap[i], va_arg (va, u32));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_f64:
      vec_validate (a->values.as_f64, i);
      a->values.as_f64[i] = va_arg (va, f64);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_string:
      {
	char * fmt = va_arg (va, char *);
	vec_validate (a->values.as_string, i);
	a->values.as_string[i] = va_format (a->values.as_string[i], fmt, &va);
	break;
      }
    default:
      ASSERT (0);
      break;
    }
}

u32 asn_app_add_user_attribute (asn_app_main_t * am, asn_app_attribute_type_t type, char * fmt, ...)
{
  asn_app_attribute_t * pa;
  va_list va;
  va_start (va, fmt);
  vec_add2 (am->user_attributes, pa, 1);
  pa->type = type;
  pa->index = pa - am->user_attributes;
  pa->name = va_format (0, fmt, &va);
  va_end (va);

  if (! am->user_attribute_by_name)
    am->user_attribute_by_name = hash_create_vec (0, sizeof (pa->name[0]), sizeof (uword));
  
  hash_set_mem (am->user_attribute_by_name, pa->name, pa->index);

  return pa->index;
}

u32 asn_app_add_oneof_user_attribute (asn_app_main_t * am, u32 ai, char * fmt, ...)
{
  asn_app_attribute_t * pa = vec_elt_at_index (am->user_attributes, ai);

  u8 * choice = 0;
  va_list va;
  va_start (va, fmt);
  choice = va_format (choice, fmt, &va);
  va_end (va);

  ASSERT (pa->type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice
	  || pa->type == ASN_APP_ATTRIBUTE_TYPE_oneof_multiple_choice);

  if (! pa->oneof_index_by_value)
    pa->oneof_index_by_value = hash_create_vec (0, sizeof (choice[0]), sizeof (uword));

  /* Choice must be unique. */
  ASSERT (! hash_get (pa->oneof_index_by_value, choice));

  uword vi = vec_len (pa->oneof_values);

  hash_set_mem (pa->oneof_index_by_value, choice, vi);
  vec_add1 (pa->oneof_values, choice);

  if (vi == 1 + BITS (u8))
    {
      u32 i;
      u16 * v16;
      vec_clone (v16, pa->values.as_u8);
      vec_foreach_index (i, pa->values.as_u8)
	v16[i] = pa->values.as_u8[i];
      vec_free (pa->values.as_u8);
      pa->values.as_u16 = v16;
    }
  else if (vi == 1 + BITS (u16))
    {
      u32 i;
      u32 * v32;
      vec_clone (v32, pa->values.as_u16);
      vec_foreach_index (i, pa->values.as_u16)
	v32[i] = pa->values.as_u16[i];
      vec_free (pa->values.as_u16);
      pa->values.as_u32 = v32;
    }
  else if (vi == 1 + BITS (u32))
    {
      u32 i;
      u64 * v64;
      vec_clone (v64, pa->values.as_u32);
      vec_foreach_index (i, pa->values.as_u32)
	v64[i] = pa->values.as_u32[i];
      vec_free (pa->values.as_u32);
      pa->values.as_u64 = v64;
    }
  else if (vi == 1 + BITS (u64))
    {
      u32 i;
      uword ** as_bitmap;
      vec_clone (as_bitmap, pa->values.as_u64);
      vec_foreach_index (i, pa->values.as_u64)
	vec_add1 (as_bitmap[i], pa->values.as_u64[i]);
      vec_free (pa->values.as_u64);
      pa->values.as_bitmap = as_bitmap;
    }

  return vi;
}

clib_error_t * asn_app_main_write_to_file (asn_app_main_t * am, char * unix_file)
{
  serialize_main_t m;
  clib_error_t * error;

  error = serialize_open_unix_file (&m, unix_file);
  if (error)
    return error;
  error = serialize (&m, serialize_asn_app_main, am);
  if (! error)
    serialize_close (&m);
  serialize_main_free (&m);
  return error;
}

clib_error_t * asn_app_main_read_from_file (asn_app_main_t * am, char * unix_file)
{
  serialize_main_t m;
  clib_error_t * error;

  error = unserialize_open_unix_file (&m, unix_file);
  if (error)
    return error;
  error = unserialize (&m, unserialize_asn_app_main, am);
  if (! error)
    unserialize_close (&m);
  unserialize_main_free (&m);
  return error;
}

#define foreach_siren_user_asn_app_attribute	\
  _ (string, first_name)			\
  _ (string, last_name)				\
  _ (string, headline)				\
  _ (string, essay)				\
  _ (u32, birthday_in_days_since_jan_1970)	\
  _ (oneof_single_choice, ethnicity)		\
  _ (oneof_single_choice, gender)		\
  _ (string, sexual_orientation)		\
  _ (oneof_single_choice, style)		\
  _ (oneof_multiple_choice, seeking)		\
  _ (oneof_multiple_choice, interested_in)

typedef enum {
#define _(type,name) SIREN_USER_ATTRIBUTE_##name,
  foreach_siren_user_asn_app_attribute
#undef _
} siren_user_attribute_type_t;

static void siren_init_user_attributes (asn_app_main_t * am)
{
  {
    u32 ai;
#define _(type,name)							\
    ai = asn_app_add_user_attribute (am, ASN_APP_ATTRIBUTE_TYPE_##type, #name); \
    ASSERT (ai == SIREN_USER_ATTRIBUTE_##name);
    foreach_siren_user_asn_app_attribute;
#undef _
  }

  {
    char * genders[] = { "female", "male", "transgender", "other", };
    uword i, j;
    for (i = 0; i < ARRAY_LEN (genders); i++)
      {
	j = asn_app_add_oneof_user_attribute (am, SIREN_USER_ATTRIBUTE_gender, genders[i]);
	ASSERT (j == i);
      }
  }
}

int main (int argc, char * argv[])
{
  asn_app_main_t _am = {0}, * am = &_am;

  clib_warning ("%U", format_clib_mem_usage, /* verbose */ 0);

  siren_init_user_attributes (am);

  {
    asn_app_user_t * au;
    asn_app_attribute_t * as = am->user_attributes;

    pool_get (am->user_pool, au);
    au->index = au - am->user_pool;

    asn_app_set_attribute (as + SIREN_USER_ATTRIBUTE_first_name, au->index, "Eliot");
    asn_app_set_attribute (as + SIREN_USER_ATTRIBUTE_last_name, au->index, "Dresselhaus");
    asn_app_set_attribute (as + SIREN_USER_ATTRIBUTE_birthday_in_days_since_jan_1970, au->index, 1023);
  }    

  {
    clib_error_t * error = asn_app_main_write_to_file (am, "fart");
    if (error)
      clib_error_report (error);
  }

  asn_app_main_free (am);

  clib_warning ("%U", format_clib_mem_usage, /* verbose */ 0);

  siren_init_user_attributes (am);

  {
    clib_error_t * error = asn_app_main_read_from_file (am, "fart");
    if (error)
      clib_error_report (error);

    asn_app_main_free (am);
    clib_warning ("%U", format_clib_mem_usage, /* verbose */ 0);
  }

  return 0;
}
