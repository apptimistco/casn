#include <casn/asn_app.h>

static u32 asn_app_add_oneof_attribute_helper (asn_app_attribute_t * pa, u8 * choice);

static void
serialize_asn_app_photo (serialize_main_t * m, va_list * va)
{
  asn_app_photo_t * p = va_arg (*va, asn_app_photo_t *);
  vec_serialize (m, p->thumbnail_as_image_data, serialize_vec_8);
  vec_serialize (m, p->blob_name_for_raw_data, serialize_vec_8);
}

static void
unserialize_asn_app_photo (serialize_main_t * m, va_list * va)
{
  asn_app_photo_t * p = va_arg (*va, asn_app_photo_t *);
  vec_unserialize (m, &p->thumbnail_as_image_data, unserialize_vec_8);
  vec_unserialize (m, &p->blob_name_for_raw_data, unserialize_vec_8);
}

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
  vec_free (a->oneof_map_for_unserialize);
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
  asn_app_attribute_type_t vta = asn_app_attribute_value_type (a);
  asn_app_attribute_type_t vtu = vta;
  if (asn_app_attribute_is_oneof (a))
    vtu = a->oneof_value_type_for_unserialize;
  union {
    u8 as_u8;
    u16 as_u16;
    u32 as_u32;
    u64 as_u64;
    f64 as_f64;
    u8 * as_string;
    uword * as_bitmap;
  } vu;
  switch (vtu)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
      unserialize_integer (m, &vu.as_u8, sizeof (u8));
      vu.as_u64 = vu.as_u8;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u16:
      unserialize_integer (m, &vu.as_u16, sizeof (u16));
      vu.as_u64 = vu.as_u16;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u32:
      unserialize_integer (m, &vu.as_u32, sizeof (u32));
      vu.as_u64 = vu.as_u32;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u64:
      unserialize_integer (m, &vu.as_u64, sizeof (u64));
      break;
    case ASN_APP_ATTRIBUTE_TYPE_f64:
      unserialize (m, unserialize_f64, &vu.as_f64);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_string:
      vec_unserialize (m, &vu.as_string, unserialize_vec_8);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_bitmap:
      vu.as_bitmap = unserialize_bitmap (m);
      break;
    default:
      ASSERT (0);
      break;
    }

  switch (vta)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
      vec_validate (a->values.as_u8, i);
      a->values.as_u8[i] = vu.as_u64;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u16:
      vec_validate (a->values.as_u16, i);
      a->values.as_u16[i] = vu.as_u64;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u32:
      vec_validate (a->values.as_u32, i);
      a->values.as_u32[i] = vu.as_u64;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u64:
      vec_validate (a->values.as_u64, i);
      a->values.as_u64[i] = vu.as_u64;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_f64:
      vec_validate (a->values.as_f64, i);
      a->values.as_f64[i] = vu.as_f64;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_string:
      vec_validate (a->values.as_string, i);
      a->values.as_string[i] = vu.as_string;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_bitmap:
      vec_validate (a->values.as_bitmap, i);
      a->values.as_bitmap[i] = vu.as_bitmap;
      break;
    default:
      ASSERT (0);
      break;
    }
}

static void
serialize_asn_app_attribute_main (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  serialize_likely_small_unsigned_integer (m, vec_len (am->attributes));
  asn_app_attribute_t * a;
  vec_foreach (a, am->attributes)
    {
      asn_app_attribute_type_t value_type = asn_app_attribute_value_type (a);
      vec_serialize (m, a->name, serialize_vec_8);
      if (asn_app_attribute_is_oneof (a))
        {
          uword i;
          serialize_likely_small_unsigned_integer (m, value_type);
          serialize_likely_small_unsigned_integer (m, vec_len (a->oneof_values));
          for (i = 0; i < vec_len (a->oneof_values); i++)
            vec_serialize (m, a->oneof_values[i], serialize_vec_8);
        }
    }
}

static void
unserialize_asn_app_attribute_main (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  asn_app_attribute_t * a;
  u32 n_attrs = unserialize_likely_small_unsigned_integer (m);
  u32 i;
  vec_resize (am->attribute_map_for_unserialize, n_attrs);
  for (i = 0; i < n_attrs; i++)
    {
      u8 * name;
      uword * p;
      vec_unserialize (m, &name, unserialize_vec_8);
      if (! (p = hash_get_mem (am->attribute_by_name, name)))
        serialize_error_return (m, "unknown attribute named `%v'", name);
      vec_free (name);
      a = vec_elt_at_index (am->attributes, *p);
      am->attribute_map_for_unserialize[i] = a->index;
      if (asn_app_attribute_is_oneof (a))
        {
          uword n_oneof_values, i;
          a->oneof_value_type_for_unserialize = unserialize_likely_small_unsigned_integer (m);
          n_oneof_values = unserialize_likely_small_unsigned_integer (m);
          for (i = 0; i < n_oneof_values; i++)
            {
              u32 oi;
              vec_unserialize (m, &name, unserialize_vec_8);

	      /* One of value with index zero is always zero. */
	      if (i == 0 && vec_len (name) == 0)
		{
		  vec_free (name);
		  continue;
		}

	      ASSERT (vec_len (name) > 0);

              p = hash_get_mem (a->oneof_index_by_value, name);
              if (! p)
                oi = asn_app_add_oneof_attribute_helper (a, name);
              else
                {
                  oi = p[0];
                  vec_free (name);
                }
              vec_validate (a->oneof_map_for_unserialize, i);
              a->oneof_map_for_unserialize[i] = oi;
            }
        }
    }
}

static void
serialize_asn_app_attributes_for_index (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 vi = va_arg (*va, u32);
  asn_app_attribute_t * a;
  vec_foreach (a, am->attributes)
    serialize (m, serialize_asn_app_attribute_value, a, vi);
}

static void
unserialize_asn_app_attributes_for_index (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 vi = va_arg (*va, u32);
  u32 i;
  asn_app_attribute_t * a;
  for (i = 0; i < vec_len (am->attribute_map_for_unserialize); i++)
    {
      a = vec_elt_at_index (am->attributes, am->attribute_map_for_unserialize[i]);
      unserialize (m, unserialize_asn_app_attribute_value, a, vi);
    }
}

void * asn_app_get_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui)
{
  asn_app_attribute_t * pa = vec_elt_at_index (am->attributes, ai);
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

void asn_app_set_attribute (asn_app_attribute_main_t * am, u32 ai, u32 i, ...)
{
  asn_app_attribute_t * a = vec_elt_at_index (am->attributes, ai);
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

u32 asn_app_add_attribute (asn_app_attribute_main_t * am, asn_app_attribute_type_t type, char * fmt, ...)
{
  asn_app_attribute_t * pa;
  va_list va;
  va_start (va, fmt);
  vec_add2 (am->attributes, pa, 1);
  pa->type = type;
  pa->index = pa - am->attributes;
  pa->name = va_format (0, fmt, &va);
  va_end (va);

  if (! am->attribute_by_name)
    am->attribute_by_name = hash_create_vec (0, sizeof (pa->name[0]), sizeof (uword));
  
  hash_set_mem (am->attribute_by_name, pa->name, pa->index);

  return pa->index;
}

static u32 asn_app_add_oneof_attribute_helper (asn_app_attribute_t * pa, u8 * choice)
{
  ASSERT (pa->type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice
	  || pa->type == ASN_APP_ATTRIBUTE_TYPE_oneof_multiple_choice);

  if (! pa->oneof_index_by_value)
    pa->oneof_index_by_value = hash_create_vec (0, sizeof (choice[0]), sizeof (uword));

  {
    uword * p = hash_get (pa->oneof_index_by_value, choice);
    if (p)
      {
        vec_free (choice);
        return p[0];
      }
  }

  uword is_single = pa->type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice;
  uword vi;
  if (is_single && vec_len (pa->oneof_values) == 0)
    vec_add1 (pa->oneof_values, 0);
  vi = vec_len (pa->oneof_values);

  hash_set_mem (pa->oneof_index_by_value, choice, vi);
  vec_add1 (pa->oneof_values, choice);

  if ((is_single && vi == (1 << BITS (u8))) || (! is_single && vi == BITS (u8)))
    {
      u32 i;
      u16 * v16;
      vec_clone (v16, pa->values.as_u8);
      vec_foreach_index (i, pa->values.as_u8)
	v16[i] = pa->values.as_u8[i];
      vec_free (pa->values.as_u8);
      pa->values.as_u16 = v16;
    }
  else if ((is_single && vi == (1 << BITS (u16))) || (! is_single && vi == BITS (u16)))
    {
      u32 i;
      u32 * v32;
      vec_clone (v32, pa->values.as_u16);
      vec_foreach_index (i, pa->values.as_u16)
	v32[i] = pa->values.as_u16[i];
      vec_free (pa->values.as_u16);
      pa->values.as_u32 = v32;
    }
  else if (! is_single && vi == BITS (u32))
    {
      u32 i;
      u64 * v64;
      vec_clone (v64, pa->values.as_u32);
      vec_foreach_index (i, pa->values.as_u32)
	v64[i] = pa->values.as_u32[i];
      vec_free (pa->values.as_u32);
      pa->values.as_u64 = v64;
    }

  else if (! is_single && vi == BITS (u64))
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

u32 asn_app_add_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, char * fmt, ...)
{
  asn_app_attribute_t * pa = vec_elt_at_index (am->attributes, ai);

  u8 * choice = 0;
  va_list va;
  va_start (va, fmt);
  choice = va_format (choice, fmt, &va);
  va_end (va);

  return asn_app_add_oneof_attribute_helper (pa, choice);
}

void asn_app_set_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, u32 i, char * fmt, ...)
{
  asn_app_attribute_t * a = vec_elt_at_index (am->attributes, ai);
  uword is_single, vi;
  va_list va;
  u8 * choice;

  ASSERT (asn_app_attribute_is_oneof (a));
  is_single = a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice;

  if (! fmt && is_single)
    {
      vi = 0;
      choice = 0;
    }
  else
    {
      va_start (va, fmt);
      choice = va_format (0, fmt, &va);
      va_end (va);
  
      /* Choice freed if non-needed. */
      vi = asn_app_add_oneof_attribute_helper (a, choice);
    }

  if (is_single)
    asn_app_set_attribute (am, ai, i, vi);

  else if (a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_multiple_choice)
    {
      asn_app_attribute_type_t value_type = asn_app_attribute_value_type (a);
      switch (value_type)
        {
        case ASN_APP_ATTRIBUTE_TYPE_u8:
          vec_validate (a->values.as_u8, i);
          a->values.as_u8[i] |= 1 << vi;
          break;
        case ASN_APP_ATTRIBUTE_TYPE_u16:
          vec_validate (a->values.as_u16, i);
          a->values.as_u16[i] |= 1 << vi;
          break;
        case ASN_APP_ATTRIBUTE_TYPE_u32:
          vec_validate (a->values.as_u32, i);
          a->values.as_u32[i] |= 1 << vi;
          break;
        case ASN_APP_ATTRIBUTE_TYPE_u64:
          vec_validate (a->values.as_u64, i);
          a->values.as_u64[i] |= (u64) 1 << (u64) vi;
          break;
        case ASN_APP_ATTRIBUTE_TYPE_bitmap:
          vec_validate (a->values.as_bitmap, i);
          a->values.as_bitmap[i] = clib_bitmap_ori (a->values.as_bitmap[i], vi);
          break;
        default:
          ASSERT (0);
          break;
        }
    }
}

u8 * asn_app_get_oneof_attribute (asn_app_attribute_main_t * am, u32 ai, u32 i)
{
  asn_app_attribute_t * a = vec_elt_at_index (am->attributes, ai);
  ASSERT (a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice);
  asn_app_attribute_type_t vt = asn_app_attribute_value_type (a);

  /* 0 is always reserved for unset oneof attributes. */
  if (i >= vec_len (a->values.as_u8)
      || vec_len (a->oneof_values) == 0)
    {
      if (vec_len (a->oneof_values) > 0)
        ASSERT (a->oneof_values[0] == 0);
      return 0;
    }

  switch (vt)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
      return vec_elt (a->oneof_values, a->values.as_u8[i]);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u16:
      return vec_elt (a->oneof_values, a->values.as_u16[i]);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u32:
      return vec_elt (a->oneof_values, a->values.as_u32[i]);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u64:
      return vec_elt (a->oneof_values, a->values.as_u64[i]);
      break;
    default:
      ASSERT (0);
      break;
    }
    return 0;
}

uword * asn_app_get_oneof_attribute_multiple_choice_bitmap (asn_app_attribute_main_t * am, u32 ai, u32 i, uword * r)
{
  asn_app_attribute_t * a = vec_elt_at_index (am->attributes, ai);
  ASSERT (a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_multiple_choice);
  asn_app_attribute_type_t vt = asn_app_attribute_value_type (a);
  clib_bitmap_zero (r);
  vec_validate (r, 0);
  switch (vt)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
      r[0] = a->values.as_u8[i];
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u16:
      r[0] = a->values.as_u16[i];
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u32:
      r[0] = a->values.as_u32[i];
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u64:
      r[0] = a->values.as_u64[i];
      break;
    case ASN_APP_ATTRIBUTE_TYPE_bitmap:
      r = clib_bitmap_or (r, a->values.as_bitmap[i]);
      break;
    default:
      ASSERT (0);
      break;
    }
  return r;
}

static void asn_app_attribute_main_free (asn_app_attribute_main_t * am)
{
  asn_app_attribute_t * a;
  vec_foreach (a, am->attributes) asn_app_attribute_free (a);
  vec_free (am->attributes);
  hash_free (am->attribute_by_name);
  vec_free (am->attribute_map_for_unserialize);
}

void asn_app_user_type_free (asn_app_user_type_t * t)
{
  asn_user_type_free (&t->user_type);
  asn_app_attribute_main_free (&t->attribute_main);
}

void asn_app_main_free (asn_app_main_t * am)
{
  {
    asn_app_user_type_t * ut;
    asn_main_free (&am->asn_main);
    for (ut = am->user_types; ut < am->user_types + ARRAY_LEN (am->user_types); ut++)
      asn_app_user_type_free (ut);
  }
}

int asn_app_sort_message_by_increasing_time (asn_app_message_union_t * m0, asn_app_message_union_t * m1)
{
  f64 cmp = m0->header.time_stamp - m1->header.time_stamp;
  return cmp > 0 ? +1 : (cmp < 0 ? -1 : 0);
}

static void serialize_asn_app_text_message (serialize_main_t * m, va_list * va)
{
  asn_app_text_message_t * msg = va_arg (*va, asn_app_text_message_t *);
  vec_serialize (m, msg->text, serialize_vec_8);
}

static void unserialize_asn_app_text_message (serialize_main_t * m, va_list * va)
{
  asn_app_text_message_t * msg = va_arg (*va, asn_app_text_message_t *);
  vec_unserialize (m, &msg->text, unserialize_vec_8);
}

static void serialize_asn_app_photo_message (serialize_main_t * m, va_list * va)
{
  asn_app_photo_message_t * msg = va_arg (*va, asn_app_photo_message_t *);
  serialize (m, &msg->photo, serialize_asn_app_photo);
}

static void unserialize_asn_app_photo_message (serialize_main_t * m, va_list * va)
{
  asn_app_photo_message_t * msg = va_arg (*va, asn_app_photo_message_t *);
  unserialize (m, &msg->photo, unserialize_asn_app_photo);
}

static void serialize_asn_app_user_group_add_del_request_message (serialize_main_t * m, va_list * va)
{
  asn_app_user_group_add_del_request_message_t * msg = va_arg (*va, asn_app_user_group_add_del_request_message_t *);
  ASSERT (! msg);
}

static void unserialize_asn_app_user_group_add_del_request_message (serialize_main_t * m, va_list * va)
{
  asn_app_user_group_add_del_request_message_t * msg = va_arg (*va, asn_app_user_group_add_del_request_message_t *);
  ASSERT (! msg);
}

void
serialize_asn_app_message (serialize_main_t * m, va_list * va)
{
  asn_app_message_union_t * msg = va_arg (*va, asn_app_message_union_t *);
  asn_app_message_header_t * h = &msg->header;

  /* User and time stamp will be copied to blob header and sent to ASN server. */
  serialize_likely_small_unsigned_integer (m, h->type);

  switch (h->type)
    {
    case ASN_APP_MESSAGE_TYPE_text:
      serialize (m, serialize_asn_app_text_message, msg);
      break;

    case ASN_APP_MESSAGE_TYPE_photo:
    case ASN_APP_MESSAGE_TYPE_video:
      serialize (m, serialize_asn_app_photo_message, msg);
      break;

    case ASN_APP_MESSAGE_TYPE_user_group_add_del_request:
      serialize (m, serialize_asn_app_user_group_add_del_request_message, msg);
      break;

    case ASN_APP_MESSAGE_TYPE_friend_request:
      /* nothing to do. */
      break;
    }
}

void
unserialize_asn_app_message (serialize_main_t * m, va_list * va)
{
  asn_app_message_union_t * msg = va_arg (*va, asn_app_message_union_t *);
  asn_app_message_header_t h;
  h.type = unserialize_likely_small_unsigned_integer (m);
  switch (h.type)
    {
    case ASN_APP_MESSAGE_TYPE_text:
      unserialize (m, unserialize_asn_app_text_message, msg);
      break;

    case ASN_APP_MESSAGE_TYPE_photo:
    case ASN_APP_MESSAGE_TYPE_video:
      unserialize (m, unserialize_asn_app_photo_message, msg);
      break;

    case ASN_APP_MESSAGE_TYPE_user_group_add_del_request:
      unserialize (m, unserialize_asn_app_user_group_add_del_request_message, msg);
      break;

    case ASN_APP_MESSAGE_TYPE_friend_request:
      /* nothing to do. */
      break;

    default:
      serialize_error_return (m, "unknown message type 0x%x", h.type);
      break;
    }
}

static void
serialize_asn_app_gen_user (serialize_main_t * m, va_list * va)
{
  asn_app_gen_user_t * u = va_arg (*va, asn_app_gen_user_t *);
  asn_user_type_t * asn_ut = pool_elt (asn_user_type_pool, u->asn_user.user_type_index);
  asn_app_user_type_t * ut = CONTAINER_OF (asn_ut, asn_app_user_type_t, user_type);

  serialize (m, serialize_asn_user, &u->asn_user);
  vec_serialize (m, u->photos, serialize_asn_app_photo);
  vec_serialize (m, u->messages_by_increasing_time, serialize_asn_app_message);
  serialize (m, serialize_asn_app_attributes_for_index, &ut->attribute_main, u->asn_user.index);
}

static void
unserialize_asn_app_gen_user (serialize_main_t * m, va_list * va)
{
  asn_app_gen_user_t * u = va_arg (*va, asn_app_gen_user_t *);
  asn_user_type_t * asn_ut;
  asn_app_user_type_t * ut;
  unserialize (m, unserialize_asn_user, &u->asn_user);
  vec_unserialize (m, &u->photos, unserialize_asn_app_photo);
  vec_unserialize (m, &u->messages_by_increasing_time, unserialize_asn_app_message);

  asn_ut = pool_elt (asn_user_type_pool, u->asn_user.user_type_index);
  ut = CONTAINER_OF (asn_ut, asn_app_user_type_t, user_type);
  unserialize (m, unserialize_asn_app_attributes_for_index, &ut->attribute_main, u->asn_user.index);
}

static void
serialize_asn_app_user (serialize_main_t * m, va_list * va)
{
  asn_app_user_t * u = va_arg (*va, asn_app_user_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      serialize (m, serialize_asn_app_gen_user, &u[i].gen_user);
    }
}

static void
unserialize_asn_app_user (serialize_main_t * m, va_list * va)
{
  asn_app_user_t * u = va_arg (*va, asn_app_user_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      unserialize (m, unserialize_asn_app_gen_user, &u[i].gen_user);
    }
}

static void
serialize_asn_app_user_group (serialize_main_t * m, va_list * va)
{
  asn_app_user_group_t * u = va_arg (*va, asn_app_user_group_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      serialize (m, serialize_asn_app_gen_user, &u[i].gen_user);
    }
}

static void
unserialize_asn_app_user_group (serialize_main_t * m, va_list * va)
{
  asn_app_user_group_t * u = va_arg (*va, asn_app_user_group_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      unserialize (m, unserialize_asn_app_gen_user, &u[i].gen_user);
    }
}

static void
serialize_asn_app_event (serialize_main_t * m, va_list * va)
{
  asn_app_event_t * u = va_arg (*va, asn_app_event_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      serialize (m, serialize_asn_app_gen_user, &u[i].gen_user);
    }
}

static void
unserialize_asn_app_event (serialize_main_t * m, va_list * va)
{
  asn_app_event_t * u = va_arg (*va, asn_app_event_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      unserialize (m, unserialize_asn_app_gen_user, &u[i].gen_user);
    }
}

static void serialize_asn_app_user_type (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_user_type_enum_t t = va_arg (*va, int);
  asn_app_user_type_t * ut;
  ASSERT (t < ARRAY_LEN (am->user_types));
  ut = am->user_types + t;
  serialize (m, serialize_asn_app_attribute_main, &ut->attribute_main);
  serialize (m, serialize_asn_user_type, &am->asn_main, &ut->user_type);
}

static void unserialize_asn_app_user_type (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_user_type_enum_t t = va_arg (*va, int);
  asn_app_user_type_t * ut;
  ASSERT (t < ARRAY_LEN (am->user_types));
  ut = am->user_types + t;
  unserialize (m, unserialize_asn_app_attribute_main, &ut->attribute_main);
  unserialize (m, unserialize_asn_user_type, &am->asn_main, &ut->user_type);
}

static char * asn_app_main_serialize_magic = "asn_app_main v0";

void
serialize_asn_app_main (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  int i;

  serialize_magic (m, asn_app_main_serialize_magic, strlen (asn_app_main_serialize_magic));
  serialize (m, serialize_asn_main, &am->asn_main);
  for (i = 0; i < ARRAY_LEN (am->user_types); i++)
    serialize (m, serialize_asn_app_user_type, am, i);
}

void
unserialize_asn_app_main (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  int i;

  unserialize_check_magic (m, asn_app_main_serialize_magic,
			   strlen (asn_app_main_serialize_magic),
			   "asn_app_main");
  unserialize (m, unserialize_asn_main, &am->asn_main);
  for (i = 0; i < ARRAY_LEN (am->user_types); i++)
    unserialize (m, unserialize_asn_app_user_type, am, i);
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

static void asn_app_free_user (asn_user_t * au)
{
  asn_app_user_t * u = CONTAINER_OF (au, asn_app_user_t, gen_user.asn_user);
  asn_app_user_free (u);
}

static void asn_app_free_user_group (asn_user_t * au)
{
  asn_app_user_group_t * u = CONTAINER_OF (au, asn_app_user_group_t, gen_user.asn_user);
  asn_app_user_group_free (u);
}

static void asn_app_free_event (asn_user_t * au)
{
  asn_app_event_t * u = CONTAINER_OF (au, asn_app_user_group_t, gen_user.asn_user);
  asn_app_event_free (u);
}

void asn_app_main_init (asn_app_main_t * am)
{
  if (! am->user_types[ASN_APP_USER_TYPE_user].user_type.was_registered)
    {
      asn_user_type_t t = {
        .name = "actual user",
        .user_type_n_bytes = sizeof (asn_app_user_t),
        .user_type_offset_of_asn_user = STRUCT_OFFSET_OF (asn_app_user_t, gen_user.asn_user),
        .free_user = asn_app_free_user,
        .serialize_users = serialize_asn_app_user,
        .unserialize_users = unserialize_asn_app_user,
      };

      am->user_types[ASN_APP_USER_TYPE_user].user_type = t;
      asn_register_user_type (&am->user_types[ASN_APP_USER_TYPE_user].user_type);
    }

  if (! am->user_types[ASN_APP_USER_TYPE_user_group].user_type.was_registered)
    {
      asn_user_type_t t = {
        .name = "user group",
        .user_type_n_bytes = sizeof (asn_app_user_group_t),
        .user_type_offset_of_asn_user = STRUCT_OFFSET_OF (asn_app_user_group_t, gen_user.asn_user),
        .free_user = asn_app_free_user_group,
        .serialize_users = serialize_asn_app_user_group,
        .unserialize_users = unserialize_asn_app_user_group,
      };

      am->user_types[ASN_APP_USER_TYPE_user_group].user_type = t;
      asn_register_user_type (&am->user_types[ASN_APP_USER_TYPE_user_group].user_type);
    }

  if (! am->user_types[ASN_APP_USER_TYPE_event].user_type.was_registered)
    {
      asn_user_type_t t = {
        .name = "event",
        .user_type_n_bytes = sizeof (asn_app_event_t),
        .user_type_offset_of_asn_user = STRUCT_OFFSET_OF (asn_app_event_t, gen_user.asn_user),
        .free_user = asn_app_free_event,
        .serialize_users = serialize_asn_app_event,
        .unserialize_users = unserialize_asn_app_event,
      };

      am->user_types[ASN_APP_USER_TYPE_event].user_type = t;
      asn_register_user_type (&am->user_types[ASN_APP_USER_TYPE_event].user_type);
    }
}
