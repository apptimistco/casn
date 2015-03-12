#include <casn/asn_app.h>

static u8 * format_asn_app_user_type_enum (u8 * s, va_list * va)
{
  asn_app_user_type_enum_t x = va_arg (*va, int);
  char * t = 0;
  switch (x)
    {
#define _(f) case ASN_APP_USER_TYPE_##f: t = #f; break;
      foreach_asn_app_user_type
#undef _
    default:
      return format (s, "unknown %d", x);
    }
  vec_add (s, t, strlen (t));
  return s;
}

static u32 asn_app_add_oneof_attribute_helper (asn_app_attribute_t * pa, u8 * choice);

static void
serialize_vec_asn_app_photo (serialize_main_t * m, va_list * va)
{
  asn_app_photo_t * p = va_arg (*va, asn_app_photo_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    {
      vec_serialize (m, p[i].thumbnail_as_image_data, serialize_vec_8);
      vec_serialize (m, p[i].blob_name_for_raw_data, serialize_vec_8);
    }
}

static void
unserialize_vec_asn_app_photo (serialize_main_t * m, va_list * va)
{
  asn_app_photo_t * p = va_arg (*va, asn_app_photo_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    {
      vec_unserialize (m, &p[i].thumbnail_as_image_data, unserialize_vec_8);
      vec_unserialize (m, &p[i].blob_name_for_raw_data, unserialize_vec_8);
    }
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
  clib_bitmap_free (a->value_is_valid_bitmap);
  vec_foreach_index (i, a->oneof_values) vec_free (a->oneof_values[i]);
  vec_free (a->oneof_values);
  hash_free (a->oneof_index_by_value);
  vec_free (a->oneof_map_for_unserialize);
  vec_free (a->name);
}

static void
serialize_asn_app_attribute_value (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 ai = va_arg (*va, u32);
  u32 i = va_arg (*va, u32);
  asn_app_attribute_t * a = vec_elt_at_index (am->attributes, ai);
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
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 ai = va_arg (*va, u32);
  u32 i = va_arg (*va, u32);
  asn_app_attribute_t * a = vec_elt_at_index (am->attributes, ai);
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
serialize_asn_app_attribute_value_oneof_single_choice (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 ai = va_arg (*va, u32);
  u32 i = va_arg (*va, u32);
  u8 * v = asn_app_get_oneof_attribute (am, ai, i);
  vec_serialize (m, v, serialize_vec_8);
}

static void
unserialize_asn_app_attribute_value_oneof_single_choice (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 ai = va_arg (*va, u32);
  u32 i = va_arg (*va, u32);
  u8 * choice;
  vec_unserialize (m, &choice, unserialize_vec_8);
  asn_app_set_oneof_attribute (am, ai, i, "%v", choice);
  vec_free (choice);
}

static void
serialize_asn_app_attribute_value_oneof_multiple_choice (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 ai = va_arg (*va, u32);
  u32 i = va_arg (*va, u32);
  uword j, * b = 0;
  asn_app_attribute_t * a = vec_elt_at_index (am->attributes, ai);
  b = asn_app_get_oneof_attribute_multiple_choice_bitmap (am, ai, i, b);
  serialize_likely_small_unsigned_integer (m, clib_bitmap_count_set_bits (b));
  clib_bitmap_foreach (j, b, ({
        vec_serialize (m, a->oneof_values[j], serialize_vec_8);
      }));
}

static void
unserialize_asn_app_attribute_value_oneof_multiple_choice (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 ai = va_arg (*va, u32);
  u32 i = va_arg (*va, u32);
  uword n_set = unserialize_likely_small_unsigned_integer (m);
  while (n_set != 0)
    {
      u8 * choice;
      vec_unserialize (m, &choice, unserialize_vec_8);
      asn_app_set_oneof_attribute (am, ai, i, "%v", choice);
      vec_free (choice);
      n_set--;
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
      serialize_bitmap (m, a->value_is_valid_bitmap);
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
      a->value_is_valid_bitmap = unserialize_bitmap (m);
    }
}

static void
serialize_asn_app_attributes_for_index (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 vi = va_arg (*va, u32);
  asn_app_attribute_t * a;
  vec_foreach (a, am->attributes)
    {
      if (clib_bitmap_get (a->value_is_valid_bitmap, vi))
        serialize (m, serialize_asn_app_attribute_value, am, a - am->attributes, vi);
    }
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
      if (clib_bitmap_get (a->value_is_valid_bitmap, vi))
        unserialize (m, unserialize_asn_app_attribute_value, am, a - am->attributes, vi);
    }
}

static void
serialize_asn_app_profile_attributes_for_index (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 vi = va_arg (*va, u32);
  asn_app_attribute_t * a;
  vec_foreach (a, am->attributes)
    if (clib_bitmap_get (a->value_is_valid_bitmap, vi))
      {
        serialize_function_t * f;
        ASSERT (vec_len (a->name) > 0);
        vec_serialize (m, a->name, serialize_vec_8);
        if (asn_app_attribute_is_oneof (a))
          {
            u32 is_single = a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice;
            f = (is_single
                 ? serialize_asn_app_attribute_value_oneof_single_choice
                 : serialize_asn_app_attribute_value_oneof_multiple_choice);
          }
        else
          f = serialize_asn_app_attribute_value;
        serialize (m, f, am, a - am->attributes, vi);
      }

  /* Serialize empty name to mark end. */
  vec_serialize (m, (u8 *) 0, serialize_vec_8);
}

static void
unserialize_asn_app_profile_attributes_for_index (serialize_main_t * m, va_list * va)
{
  asn_app_attribute_main_t * am = va_arg (*va, asn_app_attribute_main_t *);
  u32 vi = va_arg (*va, u32);
  asn_app_attribute_t * a;
  clib_error_t * error = 0;

  vec_foreach (a, am->attributes)
    asn_app_invalidate_attribute (am, a->index, vi);

  while (1)
    {
      u8 * name;
      uword is_last, * p;

      vec_unserialize (m, &name, unserialize_vec_8);

      is_last = vec_len (name) == 0;
      if (! is_last)
        {
          if (! (p = hash_get_mem (am->attribute_by_name, name)))
            error = clib_error_return (0, "unknown attribute named `%v'", name);
          else
            {
              serialize_function_t * f;

              a = vec_elt_at_index (am->attributes, p[0]);
              if (asn_app_attribute_is_oneof (a))
                {
                  u32 is_single = a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice;
                  f = (is_single
                       ? unserialize_asn_app_attribute_value_oneof_single_choice
                       : unserialize_asn_app_attribute_value_oneof_multiple_choice);
                }
              else
                f = unserialize_asn_app_attribute_value;
              asn_app_validate_attribute (am, a - am->attributes, vi);
              unserialize (m, f, am, a - am->attributes, vi);
            }
        }

      vec_free (name);

      if (error)
        serialize_error (&m->header, error);

      if (is_last)
        break;
    }
}

void * asn_app_get_attribute (asn_app_attribute_main_t * am, u32 ai, u32 ui)
{
  asn_app_attribute_t * pa = vec_elt_at_index (am->attributes, ai);
  asn_app_attribute_type_t type = asn_app_attribute_value_type (pa);

  if (! clib_bitmap_get (pa->value_is_valid_bitmap, ui))
    return 0;

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

  a->value_is_valid_bitmap = clib_bitmap_ori (a->value_is_valid_bitmap, i);
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

void asn_app_invalidate_attribute (asn_app_attribute_main_t * am, u32 ai, u32 i)
{
  asn_app_attribute_t * a = vec_elt_at_index (am->attributes, ai);
  asn_app_attribute_type_t value_type = asn_app_attribute_value_type (a);

  a->value_is_valid_bitmap = clib_bitmap_andnoti (a->value_is_valid_bitmap, i);
  switch (value_type)
    {
    case ASN_APP_ATTRIBUTE_TYPE_u8:
      vec_validate (a->values.as_u8, i);
      a->values.as_u8[i] = 0;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u16:
      vec_validate (a->values.as_u16, i);
      a->values.as_u16[i] = 0;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u32:
      vec_validate (a->values.as_u32, i);
      a->values.as_u32[i] = 0;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_u64:
      vec_validate (a->values.as_u64, i);
      a->values.as_u64[i] = 0;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_bitmap:
      vec_validate (a->values.as_bitmap, i);
      clib_bitmap_free (a->values.as_bitmap[i]);
      break;
    case ASN_APP_ATTRIBUTE_TYPE_f64:
      vec_validate (a->values.as_f64, i);
      a->values.as_f64[i] = 0;
      break;
    case ASN_APP_ATTRIBUTE_TYPE_string:
      vec_validate (a->values.as_string, i);
      vec_free (a->values.as_string[i]);
      break;
    default:
      ASSERT (0);
      break;
    }
}

void asn_app_invalidate_all_attributes (asn_app_attribute_main_t * am, u32 i)
{
  asn_app_attribute_t * a;
  vec_foreach (a, am->attributes)
    {
      if (clib_bitmap_get (a->value_is_valid_bitmap, i))
        asn_app_invalidate_attribute (am, a - am->attributes, i);
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
  uword vi = vec_len (pa->oneof_values);

  ASSERT (choice != 0);
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
  uword is_single, is_clear, vi;
  va_list va;
  u8 * choice;

  ASSERT (asn_app_attribute_is_oneof (a));
  is_single = a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_single_choice;
  /* Zero oneof value means clear attribute value. */
  is_clear = ! fmt;
  vi = 0;

  if (! is_clear)
    {
      va_start (va, fmt);
      choice = va_format (0, fmt, &va);
      va_end (va);
  
      /* Choice freed if non-needed. */
      vi = asn_app_add_oneof_attribute_helper (a, choice);
    }

  if (is_single)
    {
      if (is_clear)
        asn_app_invalidate_attribute (am, ai, i);
      else
        asn_app_set_attribute (am, ai, i, vi);
    }

  else if (a->type == ASN_APP_ATTRIBUTE_TYPE_oneof_multiple_choice)
    {
      asn_app_attribute_type_t value_type = asn_app_attribute_value_type (a);
      if (! is_clear)
        asn_app_validate_attribute (am, ai, i);
      switch (value_type)
        {
        case ASN_APP_ATTRIBUTE_TYPE_u8:
          vec_validate (a->values.as_u8, i);
          if (is_clear)
            a->values.as_u8[i] = 0;
          else
            a->values.as_u8[i] |= 1 << vi;
          break;
        case ASN_APP_ATTRIBUTE_TYPE_u16:
          vec_validate (a->values.as_u16, i);
          if (is_clear)
            a->values.as_u16[i] = 0;
          else
            a->values.as_u16[i] |= 1 << vi;
          break;
        case ASN_APP_ATTRIBUTE_TYPE_u32:
          vec_validate (a->values.as_u32, i);
          if (is_clear)
            a->values.as_u32[i] = 0;
          else
            a->values.as_u32[i] |= 1 << vi;
          break;
        case ASN_APP_ATTRIBUTE_TYPE_u64:
          vec_validate (a->values.as_u64, i);
          if (is_clear)
            a->values.as_u64[i] = 0;
          else
            a->values.as_u64[i] |= (u64) 1 << (u64) vi;
          break;
        case ASN_APP_ATTRIBUTE_TYPE_bitmap:
          vec_validate (a->values.as_bitmap, i);
          if (is_clear)
            clib_bitmap_free (a->values.as_bitmap[i]);
          else
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

  if (! clib_bitmap_get (a->value_is_valid_bitmap, i))
    return 0;

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
  if (! clib_bitmap_get (a->value_is_valid_bitmap, i))
    return r;

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

void asn_app_free_user_with_type (asn_app_main_t * am, asn_app_user_type_enum_t user_type, u32 user_index)
{
    asn_app_user_type_t * app_ut = &am->user_types[ASN_APP_USER_TYPE_event];
    asn_user_type_t * ut = &app_ut->user_type;
    asn_user_t * au = asn_user_by_index_and_type (user_index, ut->index);
    ut->free_user (au);
    asn_app_invalidate_all_attributes (&app_ut->attribute_main, user_index);
    pool_put_index (ut->user_pool, user_index);
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
    hash_free (am->place_index_by_unique_id);
  }
}

void asn_app_user_messages_free (asn_app_user_messages_t * m)
{
  uword ti, ui;
  vec_foreach_index (ti, m->message_pool_by_type)
    {
      void * msg_pool = m->message_pool_by_type[ti];
      asn_app_message_type_t * mt;
      if (pool_is_free_index (msg_pool, ti))
        continue;
      mt = pool_elt (asn_app_message_type_pool, ti);
      if (mt->free)
        vec_foreach_index (ui, msg_pool)
          {
            asn_app_message_header_t * msg = msg_pool + mt->user_msg_n_bytes * ui + mt->user_msg_offset_of_message_header;
            mt->free (msg);
          }
      pool_free (msg_pool);
    }
  vec_free (m->message_pool_by_type);
  mhash_free (&m->message_ref_by_time_stamp);
  memset (m, 0, sizeof (m[0]));
}

static void serialize_asn_app_message_header (serialize_main_t * m, va_list * va)
{
  asn_app_message_header_t * h = va_arg (*va, asn_app_message_header_t *);

  serialize_likely_small_unsigned_integer (m, h->ref.type_index);
  serialize_likely_small_unsigned_integer (m, h->from_user_index);
  serialize (m, serialize_64, h->time_stamp_in_nsec_from_1970);
}

static void unserialize_asn_app_message_header (serialize_main_t * m, va_list * va)
{
  asn_app_message_header_t * h = va_arg (*va, asn_app_message_header_t *);
  
  memset (h, 0, sizeof (h[0]));
  h->ref.type_index = unserialize_likely_small_unsigned_integer (m);
  h->from_user_index = unserialize_likely_small_unsigned_integer (m);
  unserialize (m, unserialize_64, &h->time_stamp_in_nsec_from_1970);
}

static void serialize_pool_asn_app_message (serialize_main_t * m, va_list * va)
{
  asn_app_message_type_t * mt = va_arg (*va, asn_app_message_type_t *);
  void * msgs = va_arg (*va, void *);
  u32 n_msgs = va_arg (*va, u32);
  void * u = msgs;
  u32 i;
  for (i = 0; i < n_msgs; i++)
    {
      asn_app_message_header_t * h = u + mt->user_msg_offset_of_message_header;
      serialize (m, serialize_asn_app_message_header, h);
      if (mt->serialize)
        serialize (m, mt->serialize, u);
      u += mt->user_msg_n_bytes;
    }
}

static void unserialize_pool_asn_app_message (serialize_main_t * m, va_list * va)
{
  asn_app_message_type_t * mt = va_arg (*va, asn_app_message_type_t *);
  void * msgs = va_arg (*va, void *);
  u32 n_msgs = va_arg (*va, u32);
  void * u = msgs;
  u32 i;
  for (i = 0; i < n_msgs; i++)
    {
      asn_app_message_header_t * h = u + mt->user_msg_offset_of_message_header;
      unserialize (m, unserialize_asn_app_message_header, h);
      if (mt->unserialize)
        unserialize (m, mt->unserialize, u);
      u += mt->user_msg_n_bytes;
    }
}

static void serialize_asn_app_user_messages (serialize_main_t * m, va_list * va)
{
  asn_app_user_messages_t * msgs = va_arg (*va, asn_app_user_messages_t *);
  asn_app_message_type_t * mt;
  uword ti;
  vec_foreach_index (ti, msgs->message_pool_by_type)
    {
      mt = pool_elt (asn_app_message_type_pool, ti);
      serialize_cstring (m, mt->name);
      serialize (m, serialize_pool_with_arg, msgs->message_pool_by_type[ti], mt->user_msg_n_bytes,
                 serialize_pool_asn_app_message, mt);
    }
  serialize_cstring (m, "");
}

static uword
asn_app_add_user_message (asn_app_user_messages_t * um,
                          asn_app_message_header_t * h,
                          uword maybe_duplicate)
{
  uword was_duplicate = 0;

  ASSERT (h->time_stamp_in_nsec_from_1970 != 0);

  if (! um->message_ref_by_time_stamp.hash)
    mhash_init (&um->message_ref_by_time_stamp,
                /* value size */ sizeof (asn_app_message_ref_t),
                /* key size */ STRUCT_SIZE_OF (asn_app_message_header_t, time_stamp_in_nsec_from_1970));

  if (maybe_duplicate
      && mhash_get (&um->message_ref_by_time_stamp, &h->time_stamp_in_nsec_from_1970))
    was_duplicate = 1;
  else
    {
      mhash_set_mem (&um->message_ref_by_time_stamp, &h->time_stamp_in_nsec_from_1970,
                     (uword *) &h->ref, /* old_value */ 0);

      if (h->time_stamp_in_nsec_from_1970 > um->most_recent_msg_header.time_stamp_in_nsec_from_1970)
        um->most_recent_msg_header = h[0];
    }

  return was_duplicate;
}

static void unserialize_asn_app_user_messages (serialize_main_t * m, va_list * va)
{
  asn_app_user_messages_t * msgs = va_arg (*va, asn_app_user_messages_t *);
  asn_app_message_type_t * mt;
  while (1)
    {
      char * name;
      clib_error_t * error = 0;
      uword i, is_terminal;

      unserialize_cstring (m, &name);
      is_terminal = vec_len (name) == 0;
      mt = 0;
      if (! is_terminal)
        {
          mt = asn_app_message_type_by_name (name);
          if (! mt)
            error = clib_error_return (0, "unknown message type %s", name);
        }
      vec_free (name);
      if (error)
        serialize_error (&m->header, error);

      if (is_terminal)
        break;

      vec_validate (msgs->message_pool_by_type, mt->index);
      unserialize (m, unserialize_pool_with_arg,
                   &msgs->message_pool_by_type[mt->index],
                   mt->user_msg_n_bytes,
                   unserialize_pool_asn_app_message, mt);

      for (i = 0; i < vec_len (msgs->message_pool_by_type[mt->index]); i++)
        {
          if (pool_is_free_index (msgs->message_pool_by_type[mt->index], i))
            continue;

          asn_app_message_header_t * h = (msgs->message_pool_by_type[mt->index]
                                          + i*mt->user_msg_n_bytes
                                          + mt->user_msg_offset_of_message_header);

          h->ref.pool_index = i;

          asn_app_add_user_message (msgs, h, /* maybe_duplicate */ 0);
        }
    }
}

static void
serialize_asn_app_gen_user (serialize_main_t * m, va_list * va)
{
  asn_app_gen_user_t * u = va_arg (*va, asn_app_gen_user_t *);
  asn_user_type_t * asn_ut = pool_elt (asn_user_type_pool, u->asn_user.user_type_index);
  asn_app_user_type_t * ut = CONTAINER_OF (asn_ut, asn_app_user_type_t, user_type);

  serialize (m, serialize_asn_user, &u->asn_user);
  vec_serialize (m, u->photos, serialize_vec_asn_app_photo);
  serialize (m, serialize_asn_app_user_messages, &u->user_messages);
  serialize (m, serialize_asn_app_attributes_for_index, &ut->attribute_main, u->asn_user.index);
}

static void
unserialize_asn_app_gen_user (serialize_main_t * m, va_list * va)
{
  asn_app_gen_user_t * u = va_arg (*va, asn_app_gen_user_t *);
  asn_user_type_t * asn_ut;
  asn_app_user_type_t * ut;
  unserialize (m, unserialize_asn_user, &u->asn_user);
  vec_unserialize (m, &u->photos, unserialize_vec_asn_app_photo);
  unserialize (m, unserialize_asn_app_user_messages, &u->user_messages);

  asn_ut = pool_elt (asn_user_type_pool, u->asn_user.user_type_index);
  ut = CONTAINER_OF (asn_ut, asn_app_user_type_t, user_type);
  unserialize (m, unserialize_asn_app_attributes_for_index, &ut->attribute_main, u->asn_user.index);
}

static void serialize_set_of_users_hash (serialize_main_t * m, va_list * va)
{
  uword * hash = va_arg (*va, uword *);
  hash_pair_t * p;

  serialize_likely_small_unsigned_integer (m, hash_elts (hash));
  hash_foreach_pair (p, hash, serialize_likely_small_unsigned_integer (m, p->key));
}

static void unserialize_set_of_users_hash (serialize_main_t * m, va_list * va)
{
  uword ** hash = va_arg (*va, uword **);
  uword i, n_users = unserialize_likely_small_unsigned_integer (m);
  uword * result = 0;
  if (n_users > 0)
    {
      result = hash_create (sizeof (uword), /* value bytes */ 0);
      for (i = 0; i < n_users; i++)
        {
          uword ui = unserialize_likely_small_unsigned_integer (m);
          hash_set1 (result, ui);
        }
    }
  *hash = result;
}

static void serialize_asn_app_user_check_in_at_place (serialize_main_t * m, va_list * va)
{
  asn_app_user_check_in_at_place_t * ci = va_arg (*va, asn_app_user_check_in_at_place_t *);
  vec_serialize (m, ci->message, serialize_vec_8);
  serialize (m, serialize_64, ci->time_stamp_in_nsec_from_1970);
  serialize_data (m, ci->user_key.data, sizeof (ci->user_key.data));
}

static void unserialize_asn_app_user_check_in_at_place (serialize_main_t * m, va_list * va)
{
  asn_app_user_check_in_at_place_t * ci = va_arg (*va, asn_app_user_check_in_at_place_t *);
  vec_unserialize (m, &ci->message, unserialize_vec_8);
  unserialize (m, unserialize_64, &ci->time_stamp_in_nsec_from_1970);
  unserialize_data (m, ci->user_key.data, sizeof (ci->user_key.data));
}

static void serialize_vec_asn_app_user_check_in_at_place (serialize_main_t * m, va_list * va)
{
  asn_app_user_check_in_at_place_t * ci = va_arg (*va, asn_app_user_check_in_at_place_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    serialize (m, serialize_asn_app_user_check_in_at_place, &ci[i]);
}

static void unserialize_vec_asn_app_user_check_in_at_place (serialize_main_t * m, va_list * va)
{
  asn_app_user_check_in_at_place_t * ci = va_arg (*va, asn_app_user_check_in_at_place_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    unserialize (m, unserialize_asn_app_user_check_in_at_place, &ci[i]);
}

static void
serialize_pool_asn_app_user (serialize_main_t * m, va_list * va)
{
  asn_app_user_t * u = va_arg (*va, asn_app_user_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      serialize (m, serialize_asn_app_gen_user, &u[i].gen_user);
      serialize (m, serialize_set_of_users_hash, u[i].user_friends);
      serialize (m, serialize_set_of_users_hash, u[i].events_rsvpd_for_user);
      vec_serialize (m, u[i].check_ins, serialize_vec_asn_app_user_check_in_at_place);
    }
}

static void
unserialize_pool_asn_app_user (serialize_main_t * m, va_list * va)
{
  asn_app_user_t * u = va_arg (*va, asn_app_user_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      unserialize (m, unserialize_asn_app_gen_user, &u[i].gen_user);
      unserialize (m, unserialize_set_of_users_hash, &u[i].user_friends);
      unserialize (m, unserialize_set_of_users_hash, &u[i].events_rsvpd_for_user);
      vec_unserialize (m, &u[i].check_ins, unserialize_vec_asn_app_user_check_in_at_place);
    }
}

static void
serialize_pool_asn_app_user_group (serialize_main_t * m, va_list * va)
{
  asn_app_user_group_t * u = va_arg (*va, asn_app_user_group_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      serialize (m, serialize_asn_app_gen_user, &u[i].gen_user);
      serialize (m, serialize_set_of_users_hash, u[i].group_users);
    }
}

static void
unserialize_pool_asn_app_user_group (serialize_main_t * m, va_list * va)
{
  asn_app_user_group_t * u = va_arg (*va, asn_app_user_group_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      unserialize (m, unserialize_asn_app_gen_user, &u[i].gen_user);
      unserialize (m, unserialize_set_of_users_hash, &u[i].group_users);
    }
}

static void
serialize_asn_app_location (serialize_main_t * m, va_list * va)
{
  asn_app_location_t * l = va_arg (*va, asn_app_location_t *);
  uword i;

  vec_serialize (m, l->unique_id, serialize_vec_8);
  serialize_likely_small_unsigned_integer (m, vec_len (l->address_lines));
  vec_foreach_index (i, l->address_lines)
    vec_serialize (m, l->address_lines[i], serialize_vec_8);
  vec_serialize (m, l->thumbnail_as_image_data, serialize_vec_8);
  serialize (m, serialize_asn_position_on_earth, &l->position_on_earth);
}

static void
unserialize_asn_app_location (serialize_main_t * m, va_list * va)
{
  asn_app_location_t * l = va_arg (*va, asn_app_location_t *);
  uword i;

  vec_unserialize (m, &l->unique_id, unserialize_vec_8);
  vec_reset_length (l->address_lines);
  i = unserialize_likely_small_unsigned_integer (m);
  vec_resize (l->address_lines, i);
  vec_foreach_index (i, l->address_lines)
    vec_unserialize (m, &l->address_lines[i], unserialize_vec_8);
  vec_unserialize (m, &l->thumbnail_as_image_data, unserialize_vec_8);
  unserialize (m, unserialize_asn_position_on_earth, &l->position_on_earth);
}

static void
serialize_pool_asn_app_event (serialize_main_t * m, va_list * va)
{
  asn_app_event_t * es = va_arg (*va, asn_app_event_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      serialize (m, serialize_asn_app_gen_user, &es[i].gen_user);
      serialize (m, serialize_asn_app_location, &es[i].location);
      serialize (m, serialize_set_of_users_hash, es[i].users_rsvpd_for_event);
      serialize (m, serialize_set_of_users_hash, es[i].users_invited_to_event);
      serialize (m, serialize_set_of_users_hash, es[i].groups_invited_to_event);
    }
}

static void
unserialize_pool_asn_app_event (serialize_main_t * m, va_list * va)
{
  asn_app_event_t * es = va_arg (*va, asn_app_event_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      unserialize (m, unserialize_asn_app_gen_user, &es[i].gen_user);
      unserialize (m, unserialize_asn_app_location, &es[i].location);
      unserialize (m, unserialize_set_of_users_hash, &es[i].users_rsvpd_for_event);
      unserialize (m, unserialize_set_of_users_hash, &es[i].users_invited_to_event);
      unserialize (m, unserialize_set_of_users_hash, &es[i].groups_invited_to_event);
    }
}

static void
serialize_pool_asn_app_place (serialize_main_t * m, va_list * va)
{
  asn_app_place_t * ps = va_arg (*va, asn_app_place_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      serialize (m, serialize_asn_app_gen_user, &ps[i].gen_user);
      serialize (m, serialize_asn_app_location, &ps[i].location);
      vec_serialize (m, ps[i].recent_check_ins_at_place, serialize_vec_asn_app_user_check_in_at_place);
    }
}

static void
unserialize_pool_asn_app_place (serialize_main_t * m, va_list * va)
{
  asn_app_place_t * ps = va_arg (*va, asn_app_place_t *);
  u32 n_users = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n_users; i++)
    {
      unserialize (m, unserialize_asn_app_gen_user, &ps[i].gen_user);
      unserialize (m, unserialize_asn_app_location, &ps[i].location);
      vec_unserialize (m, &ps[i].recent_check_ins_at_place, unserialize_vec_asn_app_user_check_in_at_place);
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

static void
serialize_asn_app_profile_for_gen_user (serialize_main_t * m, va_list * va)
{
  asn_app_user_type_t * ut = va_arg (*va, asn_app_user_type_t *);
  asn_app_gen_user_t * u = va_arg (*va, asn_app_gen_user_t *);
  serialize (m, serialize_asn_app_profile_attributes_for_index, &ut->attribute_main, u->asn_user.index);
  vec_serialize (m, u->photos, serialize_vec_asn_app_photo);
}

static void
unserialize_asn_app_profile_for_gen_user (serialize_main_t * m, va_list * va)
{
  asn_app_user_type_t * ut = va_arg (*va, asn_app_user_type_t *);
  asn_app_gen_user_t * u = va_arg (*va, asn_app_gen_user_t *);
  unserialize (m, unserialize_asn_app_profile_attributes_for_index, &ut->attribute_main, u->asn_user.index);
  vec_unserialize (m, &u->photos, unserialize_vec_asn_app_photo);
}

static void
serialize_asn_app_profile_for_user (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_user_t * u = va_arg (*va, asn_app_user_t *);
  asn_app_user_type_t * ut = &am->user_types[ASN_APP_USER_TYPE_user];
  serialize_magic (m, ut->user_type.name, strlen (ut->user_type.name));
  serialize (m, serialize_asn_app_profile_for_gen_user, ut, &u->gen_user);
}

static void
unserialize_asn_app_profile_for_user (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_user_t * u = va_arg (*va, asn_app_user_t *);
  asn_app_user_type_t * ut = &am->user_types[ASN_APP_USER_TYPE_user];
  unserialize_check_magic (m, ut->user_type.name, strlen (ut->user_type.name), "asn_app_user_for_profile");
  unserialize (m, unserialize_asn_app_profile_for_gen_user, ut, &u->gen_user);
}

static void
serialize_asn_app_profile_for_user_group (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_user_group_t * u = va_arg (*va, asn_app_user_group_t *);
  asn_app_user_type_t * ut = &am->user_types[ASN_APP_USER_TYPE_user_group];
  serialize_magic (m, ut->user_type.name, strlen (ut->user_type.name));
  serialize (m, serialize_asn_app_profile_for_gen_user, ut, &u->gen_user);
}

static void
unserialize_asn_app_profile_for_user_group (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_user_group_t * u = va_arg (*va, asn_app_user_group_t *);
  asn_app_user_type_t * ut = &am->user_types[ASN_APP_USER_TYPE_user_group];
  unserialize_check_magic (m, ut->user_type.name, strlen (ut->user_type.name), "asn_app_user_group_for_profile");
  unserialize (m, unserialize_asn_app_profile_for_gen_user, ut, &u->gen_user);
}

static void
serialize_asn_app_profile_for_event (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_event_t * e = va_arg (*va, asn_app_event_t *);
  asn_app_user_type_t * ut = &am->user_types[ASN_APP_USER_TYPE_event];
  serialize_magic (m, ut->user_type.name, strlen (ut->user_type.name));
  serialize (m, serialize_asn_app_profile_for_gen_user, ut, &e->gen_user);
  serialize (m, serialize_asn_app_location, &e->location);
}

static void
unserialize_asn_app_profile_for_event (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_event_t * e = va_arg (*va, asn_app_event_t *);
  asn_app_user_type_t * ut = &am->user_types[ASN_APP_USER_TYPE_event];
  unserialize_check_magic (m, ut->user_type.name, strlen (ut->user_type.name), "asn_app_event_for_profile");
  unserialize (m, unserialize_asn_app_profile_for_gen_user, ut, &e->gen_user);
  unserialize (m, unserialize_asn_app_location, &e->location);
}

static void
serialize_asn_app_profile_for_place (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_place_t * p = va_arg (*va, asn_app_place_t *);
  asn_app_user_type_t * ut = &am->user_types[ASN_APP_USER_TYPE_place];
  serialize_magic (m, ut->user_type.name, strlen (ut->user_type.name));
  serialize (m, serialize_asn_app_profile_for_gen_user, ut, &p->gen_user);
  serialize (m, serialize_asn_app_location, &p->location);
}

static void
unserialize_asn_app_profile_for_place (serialize_main_t * m, va_list * va)
{
  asn_app_main_t * am = va_arg (*va, asn_app_main_t *);
  asn_app_place_t * p = va_arg (*va, asn_app_place_t *);
  asn_app_user_type_t * ut = &am->user_types[ASN_APP_USER_TYPE_place];
  unserialize_check_magic (m, ut->user_type.name, strlen (ut->user_type.name), "asn_app_place_for_profile");
  unserialize (m, unserialize_asn_app_profile_for_gen_user, ut, &p->gen_user);
  unserialize (m, unserialize_asn_app_location, &p->location);
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

static void asn_app_place_free (asn_app_place_t * p, int free_gen_user)
{
  if (free_gen_user)
    asn_app_gen_user_free (&p->gen_user);
  asn_app_location_free (&p->location);
  {
    asn_app_user_check_in_at_place_t * ci;
    vec_foreach (ci, p->recent_check_ins_at_place)
      asn_app_user_check_in_at_place_free (ci);
    vec_free (p->recent_check_ins_at_place);
  }
}

static void asn_app_free_place (asn_user_t * au)
{
  asn_app_place_t * p = CONTAINER_OF (au, asn_app_user_group_t, gen_user.asn_user);
  asn_app_place_free (p, /* free_gen_user */ 1);
}

static char * asn_app_user_blob_name = "asn_app_user";

static clib_error_t *
asn_app_user_update_blob_helper (asn_app_main_t * app_main,
                                 asn_app_user_type_enum_t user_type,
                                 u32 user_index,
                                 u32 is_new_user)
{
  asn_main_t * am = &app_main->asn_main;
  asn_app_user_type_t * app_ut;
  asn_user_type_t * ut;
  serialize_main_t m;
  void * app_user;
  asn_user_t * au;
  u8 * v;
  clib_error_t * error = 0;

  ASSERT (user_type < ARRAY_LEN (app_main->user_types));
  app_ut = app_main->user_types + user_type;
  ut = &app_ut->user_type;

  ASSERT (! pool_is_free_index (ut->user_pool, user_index));
  app_user = ut->user_pool + user_index * ut->user_type_n_bytes;
  au = app_user + ut->user_type_offset_of_asn_user;

  serialize_open_vector (&m, 0);
  serialize_likely_small_unsigned_integer (&m, user_type);
  error = serialize (&m, app_ut->serialize_blob_contents, app_main, app_user);
  if (error)
    goto done;
  v = serialize_close_vector (&m);

  {
    u8 * blob_name;

    blob_name = 0;
    if (! asn_is_user_for_ref (au, &am->self_user_ref))
      blob_name = format (blob_name, "~%U/",
                          format_hex_bytes, au->crypto_keys.public.encrypt_key, sizeof (au->crypto_keys.public.encrypt_key));
    blob_name = format (blob_name, "%s", asn_app_user_blob_name);

    error = asn_socket_exec (am, 0, 0, "blob%c%v%c-%c%c%v", 0, blob_name, 0, 0, 0, v);
    vec_free (blob_name);
  }

  if (app_ut->did_update_user)
    app_ut->did_update_user (au, is_new_user);

 done:
  vec_free (v);
  return error;
}

clib_error_t *
asn_app_user_update_blob (asn_app_main_t * app_main, asn_app_user_type_enum_t user_type, u32 user_index)
{ return asn_app_user_update_blob_helper (app_main, user_type, user_index, /* is_new_user */ 0); }

/* Handler for blobs written with previous function. */
static clib_error_t *
asn_app_user_blob_handler (asn_blob_handler_t * bh, asn_pdu_blob_t * blob, u32 n_bytes_in_pdu)
{
  asn_main_t * am = bh->asn_main;
  clib_error_t * error = 0;
  asn_user_t * au;
  asn_app_main_t * app_main = CONTAINER_OF (am, asn_app_main_t, asn_main);
  void * app_user;
  asn_app_user_type_t * ut;
  serialize_main_t m;
  u32 is_new_user;

  au = asn_user_with_encrypt_key (am, ASN_TX, blob->owner);

  /* Never update blob for self user. */
  if (au && asn_is_user_for_ref (au, &am->self_user_ref))
    goto done;

  serialize_open_data (&m, asn_pdu_contents_for_blob (blob), asn_pdu_n_content_bytes_for_blob (blob, n_bytes_in_pdu));

  /* User type from blob. */
  {
    asn_app_user_type_enum_t t = unserialize_likely_small_unsigned_integer (&m);

    if (t >= ARRAY_LEN (app_main->user_types))
      {
        error = clib_error_return (0, "unknown user type 0x%x", t);
        goto done;
      }
    ut = app_main->user_types + t;
  }

  /* Create user from blob owner. */
  is_new_user = ! au;
  if (is_new_user)
    {
      asn_crypto_public_keys_t pk;
      /* FIXME fetch auth key. */
      memset (&pk, 0, sizeof (pk));
      memcpy (pk.encrypt_key, blob->owner, sizeof (pk.encrypt_key));
      au = asn_new_user_with_type (am, ASN_TX, ut->user_type.index,
                                   /* with_public_keys */ &pk,
                                   /* with_private_keys */ 0,
                                   /* with_random_private_keys */ 0);
    }

  app_user = (void *) au - ut->user_type.user_type_offset_of_asn_user;
  error = unserialize (&m, ut->unserialize_blob_contents, app_main, app_user);
  serialize_close (&m);

  if (! error && ut->did_update_user)
    ut->did_update_user (au, is_new_user);

 done:
  return error;
}

typedef struct {
  asn_user_key_t key;
  asn_user_t * user;
} asn_user_and_key_t;

typedef struct {
  u32 n_unknown_users;
  /* User 0 is owner; users > 0 are subscribers. */
  asn_user_and_key_t * users;
  uword blob_type;
} asn_app_users_lookup_t;

always_inline void
asn_app_users_lookup_free (asn_app_users_lookup_t * l)
{ vec_free (l->users); }

static void lookup_users (asn_main_t * am, asn_app_users_lookup_t * lu)
{
  uword i;
  lu->n_unknown_users = 0;
  vec_foreach_index (i, lu->users)
    {
      lu->users[i].user = asn_user_with_encrypt_key (am, ASN_TX, lu->users[i].key.data);
      lu->n_unknown_users += ! lu->users[i].user;
    }
}

static void handle_subscribers (asn_main_t * am, asn_app_users_lookup_t * lu)
{
  asn_user_t * owner = lu->users[0].user;
  asn_app_user_type_t * app_ut = asn_app_user_type_for_user (owner);
  asn_user_ref_t * urs = 0;
  uword i;

  ASSERT (lu->n_unknown_users == 0);
  ASSERT (app_ut->update_subscribers);

  for (i = 1; i < vec_len (lu->users); i++)
    {
      asn_user_ref_t r;
      r.user_index = lu->users[i].user->index;
      r.type_index = lu->users[i].user->user_type_index;
      vec_add1 (urs, r);
    }

  app_ut->update_subscribers (am, owner, lu->blob_type, urs, vec_len (urs));

  if (app_ut->did_update_user)
    app_ut->did_update_user (owner, /* is_new_user */ 0);
}

typedef struct {
  asn_exec_ack_handler_t ack_handler;
  asn_app_users_lookup_t * users_lookup;
  u32 user_index;
} learn_users_exec_ack_handler_t;

static void
learn_users_exec_ack_handler_free (asn_exec_ack_handler_t * ah, u32 force_free)
{
  learn_users_exec_ack_handler_t * lah;
  asn_app_users_lookup_t * lu;

  if (! force_free)
    return;

  lah = CONTAINER_OF (ah, learn_users_exec_ack_handler_t, ack_handler);
  lu = lah->users_lookup;

  ASSERT (lu->n_unknown_users > 0);
  lu->n_unknown_users--;
  if (lu->n_unknown_users == 0)
    {
      asn_app_users_lookup_free (lu);
      clib_mem_free (lu);
    }
}

static clib_error_t *
learn_user_for_subscribers_exec_ack_handler (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  clib_error_t * error = 0;
  asn_user_t * au;
  asn_user_type_t * ut;
  asn_user_ref_t user_ref;
  learn_users_exec_ack_handler_t * lah
    = CONTAINER_OF (ah, learn_users_exec_ack_handler_t, ack_handler);
  asn_app_users_lookup_t * lu = lah->users_lookup;
  asn_user_and_key_t * uk = vec_elt_at_index (lu->users, lah->user_index);

  error = asn_learn_user_from_ack (ah->asn_main, ack, n_bytes_ack_data, uk->key.data,
                                   &user_ref);
  if (error)
    goto done;

  au = asn_user_by_ref (&user_ref);
  ut = pool_elt (asn_user_type_pool, user_ref.type_index);

  if (ut->did_learn_new_user)
    ut->did_learn_new_user (au, /* is_place */ 0);

  ASSERT (lu->n_unknown_users > 0);
  lu->n_unknown_users -= 1;

  if (lu->n_unknown_users == 0)
    {
      /* lu will be freed by learn_user_for_subscribers_exec_ack_handler_free */
      lookup_users (ah->asn_main, lu);
      handle_subscribers (ah->asn_main, lu);
    }

 done:
  return error;
}

static clib_error_t *
asn_app_subscribers_blob_handler (asn_blob_handler_t * bh, asn_pdu_blob_t * blob, u32 n_bytes_in_pdu)
{
  asn_main_t * am = bh->asn_main;
  asn_socket_t * as = bh->asn_socket;
  clib_error_t * error = 0;
  asn_user_key_t * subscribers = asn_pdu_contents_for_blob (blob);
  u32 i, n_subscribers;
  asn_app_users_lookup_t lookup;

  memset (&lookup, 0, sizeof (lookup));

  n_subscribers = asn_pdu_n_content_bytes_for_blob (blob, n_bytes_in_pdu);
  if (n_subscribers % sizeof (subscribers[0]))
    {
      error = clib_error_return (0, "blob content length %d not a multiple of %d",
                                 n_subscribers, sizeof (subscribers[0]));
      goto done;
    }
  n_subscribers /= sizeof (subscribers[0]);

  lookup.blob_type = bh->blob_type;

  vec_resize (lookup.users, 1 + n_subscribers);
  memcpy (lookup.users[0].key.data, blob->owner, sizeof (lookup.users[0].key.data));
  for (i = 0; i < n_subscribers; i++)
    lookup.users[1 + i].key = subscribers[i];

  lookup_users (am, &lookup);
  if (lookup.n_unknown_users == 0)
    {
      handle_subscribers (am, &lookup);
      asn_app_users_lookup_free (&lookup);
    }
  else
    {
      asn_app_users_lookup_t * lu;

      lu = clib_mem_alloc_no_fail (sizeof (lookup));
      lu[0] = lookup;
      memset (&lookup, 0, sizeof (lookup)); /* poison it to avoid re-use */

      for (i = 0; i < vec_len (lookup.users); i++)
        if (! lu->users[i].user)
          {
            learn_users_exec_ack_handler_t * ah
              = asn_exec_ack_handler_create_with_function_in_container
              (learn_user_for_subscribers_exec_ack_handler,
               sizeof (learn_users_exec_ack_handler_t),
               STRUCT_OFFSET_OF (learn_users_exec_ack_handler_t, ack_handler));

            ah->ack_handler.free = learn_users_exec_ack_handler_free;
            ah->users_lookup = lu;
            ah->user_index = i;

            error = asn_socket_exec_with_ack_handler
              (am, as,
               &ah->ack_handler, "%U", format_asn_learn_user_exec_command, lu->users[i].key.data, sizeof (lu->users[i].key.data));
            if (error)
              goto done;        /* better not happen! */
          }
    }

 done:
  return error;
}

typedef struct {
  asn_exec_ack_handler_t ack_handler;
  asn_app_user_type_enum_t create_user_type;
  u32 create_user_index;
} asn_app_create_user_and_blob_ack_handler_t;

static clib_error_t *
asn_app_create_user_and_blob_ack_handler (asn_exec_ack_handler_t * asn_ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  asn_main_t * am = asn_ah->asn_main;
  asn_app_create_user_and_blob_ack_handler_t * ah = CONTAINER_OF (asn_ah, asn_app_create_user_and_blob_ack_handler_t, ack_handler);
  asn_app_main_t * app_main = CONTAINER_OF (am, asn_app_main_t, asn_main);
  struct {
    u8 private_encrypt_key[crypto_box_private_key_bytes];
    u8 private_auth_key[crypto_sign_private_key_bytes];
    u8 public_encrypt_key[crypto_box_public_key_bytes];
    u8 public_auth_key[crypto_sign_public_key_bytes];
  } * keys = (void *) ack->data;
  asn_app_user_type_t * app_ut;
  asn_user_type_t * ut;
  asn_user_t * au;

  ASSERT (ah->create_user_type < ARRAY_LEN (app_main->user_types));
  app_ut = app_main->user_types + ah->create_user_type;
  ut = &app_ut->user_type;

  ASSERT (n_bytes_ack_data == sizeof (keys[0]));

  au = asn_user_by_index_and_type (ah->create_user_index, ut->index);
  ASSERT (au != 0);

  {
    asn_crypto_keys_t ck;

    memcpy (ck.private.encrypt_key, keys->private_encrypt_key, sizeof (ck.private.encrypt_key));
    memcpy (ck.private.auth_key, keys->private_auth_key, sizeof (ck.private.auth_key));
    memcpy (ck.public.encrypt_key, keys->public_encrypt_key, sizeof (ck.public.encrypt_key));
    memcpy (ck.public.auth_key, keys->public_auth_key, sizeof (ck.public.auth_key));

    asn_user_update_keys (am, ASN_TX, au,
                          /* with_public_keys */ &ck.public,
                          /* with_private_keys */ &ck.private,
                          /* with_random_private_keys */ 0);
  }

  if (am->verbose)
    clib_warning ("newuser type %U, user-keys %U %U",
		  format_asn_user_type, ut->index,
		  format_hex_bytes, au->crypto_keys.public.encrypt_key, 8,
		  format_hex_bytes, au->crypto_keys.public.auth_key, 8);

  if (ut->did_set_user_keys)
    ut->did_set_user_keys (au);

  return asn_app_user_update_blob_helper (app_main, ah->create_user_type, ah->create_user_index, /* is_new_user */ 1);
}

clib_error_t *
asn_app_create_user_and_blob_with_type (asn_app_main_t * am, asn_app_user_type_enum_t user_type, u32 user_index)
{
  asn_app_user_type_t * app_ut;
  asn_user_type_t * ut;
  asn_app_create_user_and_blob_ack_handler_t * ah;

  ah = asn_exec_ack_handler_create_with_function_in_container
    (asn_app_create_user_and_blob_ack_handler,
     sizeof (ah[0]),
     STRUCT_OFFSET_OF (asn_app_create_user_and_blob_ack_handler_t, ack_handler));
  ah->create_user_type = user_type;
  ah->create_user_index = user_index;

  ASSERT (ah->create_user_type < ARRAY_LEN (am->user_types));
  app_ut = am->user_types + ah->create_user_type;
  ut = &app_ut->user_type;

  return asn_socket_exec_with_ack_handler (&am->asn_main, 0, &ah->ack_handler, "newuser%c-b%c%s", 0, 0, ut->name);
}

static clib_error_t *
asn_app_user_message_handler (asn_main_t * am, asn_socket_t * as,
                              asn_pdu_blob_t * blob, u32 n_bytes_in_pdu)
{
  clib_error_t * error = 0;
  asn_user_t * save_au, * from_au;
  asn_app_gen_user_t * save_gen_user = 0;
  asn_app_user_messages_t * user_msgs;
  asn_app_message_header_t * msg_header;
  asn_app_message_type_t * mt = 0;
  serialize_main_t m;
  void * msg = 0;
  char * type_name = 0;
  uword was_duplicate = 0;

  {
    asn_user_t * owner_au = asn_user_with_encrypt_key (am, ASN_TX, blob->owner);
    asn_user_t * author_au = asn_user_with_encrypt_key (am, ASN_TX, blob->author);
    if (asn_is_user_for_ref (owner_au, &am->self_user_ref))
      save_au = from_au = author_au;
    else
      {
        save_au = owner_au;
        from_au = author_au;
      }
  }

  serialize_open_data (&m,
                       asn_pdu_contents_for_blob (blob),
                       asn_pdu_n_content_bytes_for_blob (blob, n_bytes_in_pdu));

  unserialize_cstring (&m, &type_name);
  mt = asn_app_message_type_by_name (type_name);
  if (! mt)
    {
      error = clib_error_return (0, "unknown message type with name `%s'", type_name);
      goto done;
    }

  save_gen_user = CONTAINER_OF (save_au, asn_app_gen_user_t, asn_user);
  user_msgs = &save_gen_user->user_messages;

  msg = asn_app_new_message_with_type (user_msgs, mt);

  if (mt->unserialize)
    error = unserialize (&m, mt->unserialize, msg);
  serialize_close (&m);
  if (error)
    goto done;

  msg_header = msg + mt->user_msg_offset_of_message_header;
  msg_header->from_user_index = from_au->index;
  msg_header->time_stamp_in_nsec_from_1970 = clib_net_to_host_u64 (blob->time_stamp_in_nsec_from_1970);

  was_duplicate = asn_app_add_user_message (user_msgs, msg_header, /* maybe_duplicate */ 1);

  if (! was_duplicate)
    {
      asn_user_type_t * ut = pool_elt (asn_user_type_pool, save_au->user_type_index);
      asn_app_user_type_t * app_ut = CONTAINER_OF (ut, asn_app_user_type_t, user_type);
      uword learning_new_user_from_message = 0;

      if (mt->maybe_learn_new_user_from_message)
        {
          error = mt->maybe_learn_new_user_from_message (am, as, save_au, msg_header, &learning_new_user_from_message);
          if (error)
            goto done;
        }

      if (app_ut->did_receive_message && ! learning_new_user_from_message)
        app_ut->did_receive_message (save_au, msg_header);
    }

 done:
  if ((error && msg) || was_duplicate)
    asn_app_free_message_with_type (&save_gen_user->user_messages, mt, msg);
  vec_free (type_name);
  return error;
}

typedef struct {
  learn_users_exec_ack_handler_t learn_users_exec_ack_handler;
  asn_pdu_blob_t * blob_pdu;
  u32 n_bytes_in_blob_pdu;
} learn_users_for_received_message_exec_ack_handler_t;

static void
learn_users_for_received_message_exec_ack_handler_free (asn_exec_ack_handler_t * ah, u32 force_free)
{
  learn_users_for_received_message_exec_ack_handler_t * lah
    = CONTAINER_OF (ah, learn_users_for_received_message_exec_ack_handler_t, learn_users_exec_ack_handler.ack_handler);
  asn_app_users_lookup_t * lu = lah->learn_users_exec_ack_handler.users_lookup;
  if (force_free || lu->n_unknown_users == 0)
    clib_mem_free (lah->blob_pdu);
  learn_users_exec_ack_handler_free (&lah->learn_users_exec_ack_handler.ack_handler, force_free);
}

static clib_error_t *
learn_user_for_received_message_exec_ack_handler (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  clib_error_t * error = 0;
  asn_user_t * au;
  asn_user_type_t * ut;
  asn_user_ref_t user_ref;
  learn_users_for_received_message_exec_ack_handler_t * lah
    = CONTAINER_OF (ah, learn_users_for_received_message_exec_ack_handler_t, learn_users_exec_ack_handler.ack_handler);
  asn_app_users_lookup_t * lu = lah->learn_users_exec_ack_handler.users_lookup;
  asn_user_and_key_t * uk = vec_elt_at_index (lu->users, lah->learn_users_exec_ack_handler.user_index);

  error = asn_learn_user_from_ack (ah->asn_main, ack, n_bytes_ack_data, uk->key.data,
                                   &user_ref);
  if (error)
    goto done;

  au = asn_user_by_ref (&user_ref);
  ut = pool_elt (asn_user_type_pool, user_ref.type_index);

  if (ut->did_learn_new_user)
    ut->did_learn_new_user (au, /* is_place */ 0);

  ASSERT (lu->n_unknown_users > 0);
  lu->n_unknown_users -= 1;

  if (lu->n_unknown_users == 0)
    {
      lookup_users (ah->asn_main, lu);

      ASSERT (lu->n_unknown_users == 0);

      error = asn_app_user_message_handler (ah->asn_main, ah->asn_socket, lah->blob_pdu, lah->n_bytes_in_blob_pdu);
    }

 done:
  return error;
}

static clib_error_t *
asn_unnamed_blob_handler (asn_blob_handler_t * bh,
                          asn_pdu_blob_t * blob, u32 n_bytes_in_pdu)
{
  asn_main_t * am = bh->asn_main;
  asn_socket_t * as = bh->asn_socket;
  clib_error_t * error = 0;
  asn_app_users_lookup_t lookup;

  memset (&lookup, 0, sizeof (lookup));
  vec_resize (lookup.users, 2);
  memcpy (lookup.users[0].key.data, blob->author, sizeof (lookup.users[0].key.data));
  memcpy (lookup.users[1].key.data, blob->owner, sizeof (lookup.users[1].key.data));

  lookup_users (am, &lookup);

  if (lookup.n_unknown_users > 0)
    {
      asn_pdu_blob_t * blob_pdu;
      asn_app_users_lookup_t * lu;
      uword i;

      lu = clib_mem_alloc_no_fail (sizeof (lookup));
      lu[0] = lookup;

      blob_pdu = clib_mem_alloc_no_fail (n_bytes_in_pdu);
      memcpy (blob_pdu, blob, n_bytes_in_pdu);

      vec_foreach_index (i, lu->users)
        {
          learn_users_for_received_message_exec_ack_handler_t * ah;
          learn_users_exec_ack_handler_t * lah;

          if (lu->users[i].user)
            continue;

          ah = asn_exec_ack_handler_create_with_function_in_container
            (learn_user_for_received_message_exec_ack_handler,
             sizeof (learn_users_for_received_message_exec_ack_handler_t),
             STRUCT_OFFSET_OF (learn_users_for_received_message_exec_ack_handler_t, learn_users_exec_ack_handler.ack_handler));
          lah = &ah->learn_users_exec_ack_handler;

          lah->users_lookup = lu;
          lah->user_index = i;
          lah->ack_handler.free = learn_users_for_received_message_exec_ack_handler_free;
          ah->blob_pdu = blob_pdu;
          ah->n_bytes_in_blob_pdu = n_bytes_in_pdu;

          error = asn_socket_exec_with_ack_handler
            (am, as,
             &lah->ack_handler, "%U", format_asn_learn_user_exec_command, lu->users[i].key.data, sizeof (lu->users[i].key.data));
        }
    }
  else
    {
      error = asn_app_user_message_handler (am, as, blob, n_bytes_in_pdu);
      asn_app_users_lookup_free (&lookup);
    }

  return error;
}

typedef struct {
  asn_exec_ack_handler_t ack_handler;
  asn_app_message_ref_t msg_ref;
  asn_user_ref_t to_user_ref;
} asn_app_self_sent_message_blob_ack_handler_t;

static clib_error_t *
asn_app_send_message_blob_ack_handler (asn_exec_ack_handler_t * asn_ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  asn_main_t * am = asn_ah->asn_main;
  asn_app_self_sent_message_blob_ack_handler_t * ah = CONTAINER_OF (asn_ah, asn_app_self_sent_message_blob_ack_handler_t,
                                                                    ack_handler);
  clib_error_t * error = 0;
  asn_user_t * au = asn_user_by_ref (&ah->to_user_ref);
  asn_app_gen_user_t * gu = CONTAINER_OF (au, asn_app_gen_user_t, asn_user);
  asn_app_message_header_t * h = asn_app_message_header_for_ref (&gu->user_messages, &ah->msg_ref);
  asn_app_message_type_t * mt = pool_elt (asn_app_message_type_pool, h->ref.type_index);

  h->time_stamp_in_nsec_from_1970 = clib_net_to_host_u64 (ack->time_stamp_in_nsec_from_1970);

  asn_app_add_user_message (&gu->user_messages, h, /* maybe_duplicate */ 0);

  if (am->verbose)
    clib_warning ("sent %s message from self to user: type %U, key %U",
                  mt->name,
		  format_asn_user_type, au->user_type_index,
		  format_hex_bytes, au->crypto_keys.public.encrypt_key, 8);

  {
    asn_user_type_t * ut = pool_elt (asn_user_type_pool, au->user_type_index);
    asn_app_user_type_t * app_ut = CONTAINER_OF (ut, asn_app_user_type_t, user_type);

    if (app_ut->did_receive_message)
      app_ut->did_receive_message (au, h);
  }

  return error;
}

static asn_user_t *
asn_app_user_by_type_and_index (asn_app_main_t * app_main,
                                asn_app_user_type_enum_t user_type,
                                u32 user_index)
{
  asn_app_user_type_t * app_ut;
  asn_user_ref_t user_ref;

  ASSERT (user_type < ARRAY_LEN (app_main->user_types));
  app_ut = app_main->user_types + user_type;

  user_ref.user_index = user_index;
  user_ref.type_index = app_ut->user_type.index;

  return asn_user_by_ref (&user_ref);
}

static clib_error_t *
asn_app_send_message_to_user (asn_app_main_t * app_main,
                              asn_user_t * to_asn_user,
                              asn_app_message_header_t * msg_header)
{
  clib_error_t * error = 0;
  asn_main_t * am = &app_main->asn_main;
  asn_app_message_type_t * mt;
  u8 * content = 0;

  msg_header->from_user_index = am->self_user_ref.user_index;
  msg_header->time_stamp_in_nsec_from_1970 = 0; /* will be filled in by ack handler */

  {
    serialize_main_t sm;
    void * msg;
    
    serialize_open_vector (&sm, 0);

    mt = pool_elt (asn_app_message_type_pool, msg_header->ref.type_index);
    msg = (void *) msg_header - mt->user_msg_offset_of_message_header;

    serialize_cstring (&sm, mt->name);

    if (mt->serialize)
      error = serialize (&sm, mt->serialize, msg);
    if (error)
      goto done;
    content = serialize_close_vector (&sm);
  }

  {
    asn_app_self_sent_message_blob_ack_handler_t * ah;

    ah = asn_exec_ack_handler_create_with_function_in_container
      (asn_app_send_message_blob_ack_handler,
       sizeof (ah[0]),
       STRUCT_OFFSET_OF (asn_app_self_sent_message_blob_ack_handler_t, ack_handler));

    ah->to_user_ref.type_index = to_asn_user->user_type_index;
    ah->to_user_ref.user_index = to_asn_user->index;
    ah->msg_ref = msg_header->ref;

    error = asn_socket_exec_with_ack_handler
      (am, /* all client sockets */ 0,
       &ah->ack_handler,
       "blob%c~%U%c-%c%c%v", 0,
       format_hex_bytes, to_asn_user->crypto_keys.public.encrypt_key, sizeof (to_asn_user->crypto_keys.public.encrypt_key),
       0, 0, 0,
       content);
  }

 done:
  vec_free (content);
  return error;
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

static void free_asn_app_text_message (asn_app_message_header_t * h)
{
  asn_app_text_message_t * msg = CONTAINER_OF (h, asn_app_text_message_t, header);
  vec_free (msg->text);
}

asn_app_message_type_t asn_app_text_message_type = {
  .name = "text",
  .user_msg_n_bytes = sizeof (asn_app_text_message_t),
  .user_msg_offset_of_message_header = STRUCT_OFFSET_OF (asn_app_text_message_t, header),
  .serialize = serialize_asn_app_text_message,
  .unserialize = unserialize_asn_app_text_message,
  .free = free_asn_app_text_message,
};
CLIB_INIT_ADD (asn_app_message_type_t, asn_app_text_message_type);

clib_error_t *
asn_app_send_text_message_to_user (asn_app_main_t * app_main,
                                   asn_app_user_type_enum_t to_user_type,
                                   u32 to_user_index,
                                   char * fmt, ...)
{
  asn_user_t * to_asn_user;
  asn_app_gen_user_t * gen_user;
  asn_app_text_message_t * msg;
  va_list va;

  to_asn_user = asn_app_user_by_type_and_index (app_main, to_user_type, to_user_index);
  if (! to_asn_user)
    return clib_error_return (0, "unknown user with type %U and index %d",
                              format_asn_app_user_type_enum, to_user_type,
                              to_user_index);

  gen_user = CONTAINER_OF (to_asn_user, asn_app_gen_user_t, asn_user);

  msg = asn_app_new_message_with_type (&gen_user->user_messages, &asn_app_text_message_type);

  va_start (va, fmt);
  msg->text = va_format (0, fmt, &va);
  va_end (va);

  return asn_app_send_message_to_user (app_main, to_asn_user, &msg->header);
}

static void serialize_asn_app_invitation_message (serialize_main_t * m, va_list * va)
{
  asn_app_invitation_message_t * msg = va_arg (*va, asn_app_invitation_message_t *);
  serialize_likely_small_unsigned_integer (m, msg->type);
  serialize_data (m, msg->invitation_for_key.data, sizeof (msg->invitation_for_key.data));
}

static void unserialize_asn_app_invitation_message (serialize_main_t * m, va_list * va)
{
  asn_app_invitation_message_t * msg = va_arg (*va, asn_app_invitation_message_t *);
  msg->type = unserialize_likely_small_unsigned_integer (m);
  unserialize_data (m, msg->invitation_for_key.data, sizeof (msg->invitation_for_key.data));
}

typedef struct {
  asn_exec_ack_handler_t ack_handler;
  asn_user_ref_t src_user_ref;
  asn_app_message_ref_t invitation_msg_ref;
} learn_user_for_invitation_exec_ack_handler_t;

static clib_error_t *
learn_user_for_invitation_exec_ack_handler (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  clib_error_t * error = 0;
  learn_user_for_invitation_exec_ack_handler_t * lah
    = CONTAINER_OF (ah, learn_user_for_invitation_exec_ack_handler_t, ack_handler);
  asn_user_t * src_au = asn_user_by_ref (&lah->src_user_ref);
  asn_app_gen_user_t * gu = CONTAINER_OF (src_au, asn_app_gen_user_t, asn_user);
  asn_app_invitation_message_t * msg = asn_app_message_for_ref (&gu->user_messages, &lah->invitation_msg_ref);
  asn_user_ref_t learned_user_ref;

  error = asn_learn_user_from_ack (ah->asn_main, ack, n_bytes_ack_data, msg->invitation_for_key.data,
                                   &learned_user_ref);
  if (error)
    goto done;

  {
    asn_user_type_t * ut = pool_elt (asn_user_type_pool, learned_user_ref.type_index);
    asn_user_t * learned_au = asn_user_by_ref (&learned_user_ref);
    if (ut->did_learn_new_user)
      ut->did_learn_new_user (learned_au, /* is_place */ 0);
  }

  {
    asn_user_type_t * ut = pool_elt (asn_user_type_pool, src_au->user_type_index);
    asn_app_user_type_t * app_ut = CONTAINER_OF (ut, asn_app_user_type_t, user_type);
    if (app_ut->did_receive_message)
      app_ut->did_receive_message (src_au, &msg->header);
  }

 done:
  return error;
}

static clib_error_t *
asn_app_invitation_maybe_learn_new_user (asn_main_t * am, asn_socket_t * as, asn_user_t * src_au,
                                         asn_app_message_header_t * h,
                                         uword * learning_new_user_from_message)
{
  asn_app_invitation_message_t * msg = CONTAINER_OF (h, asn_app_invitation_message_t, header);
  asn_user_t * invited_user = asn_user_with_encrypt_key (am, ASN_TX, msg->invitation_for_key.data);
  clib_error_t * error = 0;
  if (! invited_user)
    {
      learn_user_for_invitation_exec_ack_handler_t * ah
        = asn_exec_ack_handler_create_with_function_in_container
        (learn_user_for_invitation_exec_ack_handler,
         sizeof (learn_user_for_invitation_exec_ack_handler_t),
         STRUCT_OFFSET_OF (learn_user_for_invitation_exec_ack_handler_t, ack_handler));

      ah->src_user_ref.user_index = src_au->index;
      ah->src_user_ref.type_index = src_au->user_type_index;
      ah->invitation_msg_ref = h->ref;

      error = asn_socket_exec_with_ack_handler
        (am, as,
         &ah->ack_handler, "%U", format_asn_learn_user_exec_command, msg->invitation_for_key.data, sizeof (msg->invitation_for_key.data));
    }
  *learning_new_user_from_message = invited_user ? 0 : 1;
  return error;
}

asn_app_message_type_t asn_app_invitation_message_type = {
  .name = "invitation",
  .user_msg_n_bytes = sizeof (asn_app_invitation_message_t),
  .user_msg_offset_of_message_header = STRUCT_OFFSET_OF (asn_app_invitation_message_t, header),
  .serialize = serialize_asn_app_invitation_message,
  .unserialize = unserialize_asn_app_invitation_message,
  .maybe_learn_new_user_from_message = asn_app_invitation_maybe_learn_new_user,
};
CLIB_INIT_ADD (asn_app_message_type_t, asn_app_invitation_message_type);

clib_error_t *
asn_app_send_invitation_message_to_user (asn_app_main_t * app_main,
                                         asn_app_user_type_enum_t invitation_user_type,
                                         u32 invitation_user_index,
                                         asn_app_user_type_enum_t to_user_type,
                                         u32 to_user_index,
                                         asn_app_invitation_type_t invitation_type)
{
  asn_user_t * to_asn_user, * invitation_asn_user;
  asn_app_gen_user_t * gen_user;
  asn_app_invitation_message_t * msg;

  to_asn_user = asn_app_user_by_type_and_index (app_main, to_user_type, to_user_index);
  if (! to_asn_user)
    return clib_error_return (0, "unknown user with type %U and index %d",
                              format_asn_app_user_type_enum, to_user_type,
                              to_user_index);

  invitation_asn_user = asn_app_user_by_type_and_index (app_main, invitation_user_type, invitation_user_index);
  if (! invitation_asn_user)
    return clib_error_return (0, "unknown user with type %U and index %d",
                              format_asn_app_user_type_enum, invitation_user_type,
                              invitation_user_index);

  gen_user = CONTAINER_OF (to_asn_user, asn_app_gen_user_t, asn_user);

  msg = asn_app_new_message_with_type (&gen_user->user_messages, &asn_app_invitation_message_type);

  msg->type = invitation_type;
  memcpy (msg->invitation_for_key.data, invitation_asn_user->crypto_keys.public.encrypt_key, sizeof (msg->invitation_for_key.data));

  return asn_app_send_message_to_user (app_main, to_asn_user, &msg->header);
}

static void
asn_app_user_update_subscribers (asn_main_t * am,
                                 asn_user_t * owner_au,
                                 asn_app_subscribers_blob_type_t blob_type,
                                 asn_user_ref_t * subscriber_user_refs, u32 n_subscriber_user_refs)
{
  asn_app_main_t * app_main = CONTAINER_OF (am, asn_app_main_t, asn_main);
  asn_app_user_t * u = CONTAINER_OF (owner_au, asn_app_user_t, gen_user.asn_user);
  asn_user_type_t * expected_user_type;
  uword ** hp, * h, i;

  expected_user_type = &app_main->user_types[ASN_APP_USER_TYPE_user].user_type;
  switch (blob_type)
    {
    case ASN_APP_SUBSCRIBERS_BLOB_TYPE_user_friends:
      hp = &u->user_friends;
      break;

    case ASN_APP_SUBSCRIBERS_BLOB_TYPE_event_groups_invited:
      hp = &u->events_rsvpd_for_user;
      expected_user_type = &app_main->user_types[ASN_APP_USER_TYPE_event].user_type;
      break;

    default:
      clib_warning ("unknown subscriber blob-type 0x%x", blob_type);
      return;
    }

  h = *hp;
  hash_free (h);
  h = hash_create (sizeof (uword), /* value bytes */ 0);
  for (i = 0; i < n_subscriber_user_refs; i++)
    {
      asn_user_t * subscriber_au = asn_user_by_ref (&subscriber_user_refs[i]);
      asn_user_type_t * subscriber_ut = asn_user_type_for_user (subscriber_au);
      if (subscriber_ut->index != expected_user_type->index)
        {
          if (am->verbose)
            clib_warning ("subscriber with wrong user type %s (expected %s) ignored",
                          subscriber_ut->name, expected_user_type->name);
        }
      else
        {
          hash_set1 (h, subscriber_au->index);
        }
    }
  *hp = h;
}

static void
asn_app_user_group_update_subscribers (asn_main_t * am,
                                       asn_user_t * owner_au,
                                       asn_app_subscribers_blob_type_t  blob_type,
                                       asn_user_ref_t * subscriber_user_refs, u32 n_subscriber_user_refs)
{
  asn_app_main_t * app_main = CONTAINER_OF (am, asn_app_main_t, asn_main);
  asn_app_user_group_t * g = CONTAINER_OF (owner_au, asn_app_user_group_t, gen_user.asn_user);
  uword i;

  hash_free (g->group_users);
  g->group_users = hash_create (sizeof (uword), /* value bytes */ 0);
  for (i = 0; i < n_subscriber_user_refs; i++)
    {
      asn_user_t * subscriber_au = asn_user_by_ref (&subscriber_user_refs[i]);
      asn_user_type_t * subscriber_ut = asn_user_type_for_user (subscriber_au);
      if (subscriber_ut->index != app_main->user_types[ASN_APP_USER_TYPE_user].user_type.index)
        {
          if (am->verbose)
            clib_warning ("subscriber with wrong user type %s ignored", subscriber_ut->name);
        }
      else
        {
          hash_set1 (g->group_users, subscriber_au->index);
        }
    }
}

static void
asn_app_event_update_subscribers (asn_main_t * am,
                                  asn_user_t * owner_au,
                                  asn_app_subscribers_blob_type_t blob_type,
                                  asn_user_ref_t * subscriber_user_refs, u32 n_subscriber_user_refs)
{
  asn_app_main_t * app_main = CONTAINER_OF (am, asn_app_main_t, asn_main);
  asn_app_event_t * e = CONTAINER_OF (owner_au, asn_app_event_t, gen_user.asn_user);
  asn_user_type_t * expected_user_type;
  uword ** hp, * h, i;

  expected_user_type = &app_main->user_types[ASN_APP_USER_TYPE_user].user_type;
  switch (blob_type)
    {
    case ASN_APP_SUBSCRIBERS_BLOB_TYPE_event_users_invited:
      hp = &e->users_invited_to_event;
      break;

    case ASN_APP_SUBSCRIBERS_BLOB_TYPE_event_groups_invited:
      hp = &e->groups_invited_to_event;
      expected_user_type = &app_main->user_types[ASN_APP_USER_TYPE_user_group].user_type;
      break;

    case ASN_APP_SUBSCRIBERS_BLOB_TYPE_event_users_rsvpd:
      hp = &e->users_rsvpd_for_event;
      break;

    default:
      clib_warning ("unknown subscriber blob-type 0x%x", blob_type);
      return;
    }

  h = *hp;
  hash_free (h);
  h = hash_create (sizeof (uword), /* value bytes */ 0);
  for (i = 0; i < n_subscriber_user_refs; i++)
    {
      asn_user_t * subscriber_au = asn_user_by_ref (&subscriber_user_refs[i]);
      asn_user_type_t * subscriber_ut = asn_user_type_for_user (subscriber_au);
      if (subscriber_ut->index != expected_user_type->index)
        {
          if (am->verbose)
            clib_warning ("subscriber with wrong user type %s (expected %s) ignored",
                          subscriber_ut->name, expected_user_type->name);
        }
      else
        {
          hash_set1 (h, subscriber_au->index);
        }
    }
  *hp = h;
}

typedef struct {
  u8 place_public_encrypt_key[crypto_box_public_key_bytes];
  u8 place_public_auth_key[crypto_sign_public_key_bytes];
  u8 place_private_encrypt_key[crypto_box_private_key_bytes];
  u8 place_private_auth_key[crypto_sign_private_key_bytes];
  asn_app_location_t location;
} asn_app_place_state_t;

static void serialize_asn_app_place_state (serialize_main_t * m, va_list * va)
{
  asn_app_place_state_t * p = va_arg (*va, asn_app_place_state_t *);
  serialize_data (m, p->place_public_encrypt_key, sizeof (p->place_public_encrypt_key));
  serialize_data (m, p->place_public_auth_key, sizeof (p->place_public_auth_key));
  serialize_data (m, p->place_private_encrypt_key, sizeof (p->place_private_encrypt_key));
  serialize_data (m, p->place_private_auth_key, sizeof (p->place_private_auth_key));
  serialize (m, serialize_asn_app_location, &p->location);
}

static void unserialize_asn_app_place_state (serialize_main_t * m, va_list * va)
{
  asn_app_place_state_t * p = va_arg (*va, asn_app_place_state_t *);

  memset (p, 0, sizeof (p[0]));
  unserialize_data (m, p->place_public_encrypt_key, sizeof (p->place_public_encrypt_key));
  unserialize_data (m, p->place_public_auth_key, sizeof (p->place_public_auth_key));
  unserialize_data (m, p->place_private_encrypt_key, sizeof (p->place_private_encrypt_key));
  unserialize_data (m, p->place_private_auth_key, sizeof (p->place_private_auth_key));
  unserialize (m, unserialize_asn_app_location, &p->location);
}

typedef struct {
  asn_exec_ack_handler_t ack_handler;
  asn_app_location_t location;
} learn_existing_place_exec_ack_handler_t;

static clib_error_t *
learn_existing_place_exec_ack_handler (asn_exec_ack_handler_t * ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  clib_error_t * error = 0;
  learn_existing_place_exec_ack_handler_t * lah = CONTAINER_OF (ah, learn_existing_place_exec_ack_handler_t, ack_handler);
  asn_app_place_state_t ps;
  asn_app_user_check_in_at_place_t * check_ins = 0;
  serialize_main_t m;

  memset (&ps, 0, sizeof (ps));

  unserialize_open_data (&m, ack->data, n_bytes_ack_data);

  /* Only learn places with check ins. */
  if (ack->status != ASN_ACK_PDU_STATUS_success || n_bytes_ack_data == 0)
    goto done;

  error = unserialize (&m, unserialize_asn_app_place_state, &ps);
  if (error)
    goto done;
  while (! unserialize_is_end_of_stream (&m))
    {
      asn_app_user_check_in_at_place_t * ci;
      vec_add2 (check_ins, ci, 1);
      error = unserialize (&m, unserialize_asn_app_user_check_in_at_place, ci);
      if (error)
        goto done;
    }
  
  {
    asn_main_t * am = ah->asn_main;
    asn_app_main_t * app_main = CONTAINER_OF (am, asn_app_main_t, asn_main);
    asn_user_t * au;
    asn_app_place_t * p;

    au = asn_user_with_encrypt_key (am, ASN_TX, ps.place_public_encrypt_key);
    if (! au)
      {
        asn_crypto_public_keys_t pk;
        asn_crypto_private_keys_t vk;
        memset (&pk, 0, sizeof (pk));
        memcpy (pk.encrypt_key, ps.place_public_encrypt_key, sizeof (pk.encrypt_key));
        memcpy (pk.auth_key, ps.place_public_auth_key, sizeof (pk.auth_key));
        memset (&vk, 0, sizeof (vk));
        memcpy (vk.encrypt_key, ps.place_private_encrypt_key, sizeof (vk.encrypt_key));
        memcpy (vk.auth_key, ps.place_private_auth_key, sizeof (vk.auth_key));
        au = asn_new_user_with_type (am, ASN_TX,
                                     app_main->user_types[ASN_APP_USER_TYPE_place].user_type.index,
                                     /* with_public_keys */ &pk,
                                     /* with_private_keys */ &vk,
                                     /* with_random_private_keys */ 0);
      }

    p = CONTAINER_OF (au, asn_app_place_t, gen_user.asn_user);
    asn_app_place_free (p, /* free_gen_user */ 0);
    p->location = ps.location;
    p->recent_check_ins_at_place = check_ins;
  }

 done:
  unserialize_close (&m);
  asn_app_location_free (&lah->location);
  return error;
}

clib_error_t * asn_app_find_existing_place_with_location (asn_app_main_t * am, asn_app_location_t * location)
{
  clib_error_t * error = 0;
  learn_existing_place_exec_ack_handler_t * ah;

  if (asn_app_place_with_unique_id (am, location->unique_id))
    goto done;

  ah = asn_exec_ack_handler_create_with_function_in_container
    (learn_existing_place_exec_ack_handler,
     sizeof (ah[0]),
     STRUCT_OFFSET_OF (learn_existing_place_exec_ack_handler_t, ack_handler));

  asn_app_location_dup (&ah->location, location);

  error = asn_socket_exec_with_ack_handler
    (&am->asn_main, /* all sockets */ 0,
     &ah->ack_handler,
     "cat%c~(id_%v)/place%c~(id_%v)/checkins/*",
     0,
     location->unique_id, 0,
     location->unique_id);
  if (error)
    goto done;

 done:
  return error;
}

static clib_error_t * do_check_in (asn_app_main_t * am, asn_app_user_t * user, asn_app_place_t * place, u8 * check_in_message)
{
  asn_app_user_check_in_at_place_t * ci;
  u64 ts = 1e9 * unix_time_now ();
  clib_error_t * error = 0;

  vec_add2 (place->recent_check_ins_at_place, ci, 1);
  ci->message = vec_dup (check_in_message);
  ci->time_stamp_in_nsec_from_1970 = ts;
  memcpy (ci->user_key.data, user->gen_user.asn_user.crypto_keys.public.encrypt_key, sizeof (ci->user_key.data));

  error = asn_save_serialized_blob (&am->asn_main, /* all client sockets */ 0,
                                    &place->gen_user.asn_user,
                                    "checkins/%U_%Lx", format_hex_bytes, ci->user_key.data, 8, ci->time_stamp_in_nsec_from_1970,
                                    serialize_asn_app_user_check_in_at_place, ci);
  if (error)
    goto done;

  vec_add2 (user->check_ins, ci, 1);
  ci->message = vec_dup (check_in_message);
  ci->time_stamp_in_nsec_from_1970 = ts;
  memcpy (ci->user_key.data, place->gen_user.asn_user.crypto_keys.public.encrypt_key, sizeof (ci->user_key.data));

  error = asn_save_serialized_blob (&am->asn_main, /* all client sockets */ 0,
                                    &user->gen_user.asn_user,
                                    "checkins/%U_%Lx", format_hex_bytes, ci->user_key.data, 8, ci->time_stamp_in_nsec_from_1970,
                                    serialize_asn_app_user_check_in_at_place, ci);
 done:
  return error;
}

typedef struct {
  asn_exec_ack_handler_t ack_handler;
  asn_app_location_t location;
  u8 * check_in_message;
} create_place_for_check_in_ack_handler_t;

static clib_error_t *
create_place_for_check_in_ack_handler (asn_exec_ack_handler_t * asn_ah, asn_pdu_ack_t * ack, u32 n_bytes_ack_data)
{
  clib_error_t * error = 0;
  asn_main_t * am = asn_ah->asn_main;
  create_place_for_check_in_ack_handler_t * ah = CONTAINER_OF (asn_ah, create_place_for_check_in_ack_handler_t, ack_handler);
  asn_app_main_t * app_main = CONTAINER_OF (am, asn_app_main_t, asn_main);
  struct {
    u8 private_encrypt_key[crypto_box_private_key_bytes];
    u8 private_auth_key[crypto_sign_private_key_bytes];
    u8 public_encrypt_key[crypto_box_public_key_bytes];
    u8 public_auth_key[crypto_sign_public_key_bytes];
  } * keys = (void *) ack->data;
  asn_crypto_keys_t ck;
  asn_user_t * au;
  asn_app_place_t * place;
  asn_app_user_t * self_user = asn_app_user_with_index (app_main, am->self_user_ref.user_index);
  asn_user_t * self_au = &self_user->gen_user.asn_user;
  asn_user_type_t * ut = &app_main->user_types[ASN_APP_USER_TYPE_place].user_type;

  memcpy (ck.private.encrypt_key, keys->private_encrypt_key, sizeof (ck.private.encrypt_key));
  memcpy (ck.private.auth_key, keys->private_auth_key, sizeof (ck.private.auth_key));
  memcpy (ck.public.encrypt_key, keys->public_encrypt_key, sizeof (ck.public.encrypt_key));
  memcpy (ck.public.auth_key, keys->public_auth_key, sizeof (ck.public.auth_key));

  au = asn_new_user_with_type (am, ASN_TX, ut->index,
                               /* with_public_keys */ &ck.public,
                               /* with_private_keys */ &ck.private,
                               /* with_random_private_keys */ 0);

  if (am->verbose)
    clib_warning ("new place unique id %v, user-keys %U %U",
                  ah->location.unique_id,
		  format_hex_bytes, au->crypto_keys.public.encrypt_key, 8,
		  format_hex_bytes, au->crypto_keys.public.auth_key, 8);

  place = CONTAINER_OF (au, asn_app_place_t, gen_user.asn_user);
  place->location = ah->location;
  memset (&ah->location, 0, sizeof (ah->location)); /* poison */

  error = do_check_in (app_main, self_user, place, ah->check_in_message);
  if (error)
    goto done;

  error = asn_save_blob_with_contents (am, /* socket */ 0, self_au, /* blob_contents */ 0,
                                       "id_%v", place->location.unique_id);
  if (error)
    goto done;

  {
    asn_app_place_state_t ps;

    memset (&ps, 0, sizeof (ps));
    memcpy (ps.place_public_encrypt_key, keys->public_encrypt_key, sizeof (ps.place_public_encrypt_key));
    memcpy (ps.place_public_auth_key, keys->public_auth_key, sizeof (ps.place_public_auth_key));
    memcpy (ps.place_private_encrypt_key, keys->private_encrypt_key, sizeof (ps.place_private_encrypt_key));
    memcpy (ps.place_private_auth_key, keys->private_auth_key, sizeof (ps.place_private_auth_key));
    ps.location = place->location;

    error = asn_save_serialized_blob (am, /* sockets */ 0, self_au,
                                      "place",
                                      serialize_asn_app_place_state, &ps);
    if (error)
      goto done;
  }

 done:
  vec_free (ah->check_in_message);
  return error;
}

clib_error_t * asn_app_check_in_at_location (asn_app_main_t * am, asn_app_location_t * location, u8 * check_in_message)
{
  asn_app_place_t * place = asn_app_place_with_unique_id (am, location->unique_id);
  asn_app_user_t * self_user = asn_app_user_with_index (am, am->asn_main.self_user_ref.user_index);
  clib_error_t * error = 0;

  if (place)
    error = do_check_in (am, self_user, place, check_in_message);
  else
    {
      create_place_for_check_in_ack_handler_t * ah;

      ah = asn_exec_ack_handler_create_with_function_in_container
        (create_place_for_check_in_ack_handler,
         sizeof (ah[0]),
         STRUCT_OFFSET_OF (create_place_for_check_in_ack_handler_t, ack_handler));
      asn_app_location_dup (&ah->location, location);
      ah->check_in_message = vec_dup (check_in_message);
      return asn_socket_exec_with_ack_handler (&am->asn_main, 0, &ah->ack_handler, "newuser%c-b%c%s", 0, 0,
                                               am->user_types[ASN_APP_USER_TYPE_place].user_type.name);
    }

  return error;
}

static clib_error_t *
asn_app_check_in_blob_handler (asn_blob_handler_t * bh, asn_pdu_blob_t * blob, u32 n_bytes_in_pdu)
{
  asn_main_t * am = bh->asn_main;
  asn_app_main_t * app_main = CONTAINER_OF (am, asn_app_main_t, asn_main);
  clib_error_t * error = 0;
  asn_app_user_check_in_at_place_t ci;
  asn_user_t * au;

  memset (&ci, 0, sizeof (ci));

  au = asn_user_with_encrypt_key (am, ASN_TX, blob->owner);
  if (! au)
    {
      error = clib_error_return (0, "unknown user with key %U", format_asn_user_key, blob->owner);
      goto done;
    }

  error = asn_unserialize_blob_contents (am, blob, n_bytes_in_pdu,
                                         unserialize_asn_app_user_check_in_at_place, &ci);
  if (error)
    goto done;

  if (au->user_type_index == app_main->user_types[ASN_APP_USER_TYPE_user].user_type.index)
    {
      asn_app_user_t * user = CONTAINER_OF (au, asn_app_user_t, gen_user.asn_user);
      vec_add1 (user->check_ins, ci);
    }
  else if (au->user_type_index == app_main->user_types[ASN_APP_USER_TYPE_place].user_type.index)
    {
      asn_app_place_t * place = CONTAINER_OF (au, asn_app_place_t, gen_user.asn_user);
      vec_add1 (place->recent_check_ins_at_place, ci);
    }
  else
    {
      error = clib_error_return (0, "unexpected user type %U", format_asn_user_type, au->user_type_index);
      goto done;
    }

  {
    asn_app_user_type_t * app_ut = asn_app_user_type_for_user (au);
    if (app_ut->did_update_user)
      app_ut->did_update_user (au, /* is_new_user */ 0);
  }

 done:
  if (error)
    asn_app_user_check_in_at_place_free (&ci);
  return error;
}

static void register_message_type (asn_app_message_type_t * mt)
{
  uword ti;

  ASSERT (mt->name != 0);
  ASSERT (mt->user_msg_n_bytes >= sizeof (asn_app_message_header_t));
  ASSERT (mt->user_msg_offset_of_message_header >= 0);
  ASSERT (mt->user_msg_offset_of_message_header + sizeof (asn_app_message_header_t) <= mt->user_msg_n_bytes);

  asn_app_message_type_pool = pool_get_free_index (asn_app_message_type_pool, sizeof (asn_app_message_type_pool[0]),
                                                   &ti);
  asn_app_message_type_pool[ti] = mt;
  mt->index = ti;
  mt->was_registered = 1;

  if (! asn_app_message_type_pool_index_by_name)
    asn_app_message_type_pool_index_by_name = hash_create_string (0, sizeof (uword));

  hash_set_mem (asn_app_message_type_pool_index_by_name, mt->name, ti);
  ASSERT (mt == asn_app_message_type_by_name (mt->name));
}

void asn_app_main_init (asn_app_main_t * am)
{
  if (pool_elts (asn_app_message_type_pool) == 0)
    {
      asn_app_message_type_t * mt;
      foreach_clib_init_with_type (mt, asn_app_message_type_t, register_message_type (mt));
    }

  asn_set_blob_handler_for_name (&am->asn_main, asn_unnamed_blob_handler, "");
  asn_set_blob_handler_for_name (&am->asn_main, asn_app_user_blob_handler, "%s", asn_app_user_blob_name);
  asn_set_blob_handler_for_name_with_type (&am->asn_main, asn_app_subscribers_blob_handler,
                                           ASN_APP_SUBSCRIBERS_BLOB_TYPE_asn_subscribers,
                                           "asn/subscribers");
  asn_set_blob_handler_for_name_with_type (&am->asn_main, asn_app_subscribers_blob_handler,
                                           ASN_APP_SUBSCRIBERS_BLOB_TYPE_user_friends,
                                           "user_friends");
  asn_set_blob_handler_for_name_with_type (&am->asn_main, asn_app_subscribers_blob_handler,
                                           ASN_APP_SUBSCRIBERS_BLOB_TYPE_user_events_rsvpd,
                                           "user_events_rsvpd");
  asn_set_blob_handler_for_name_with_type (&am->asn_main, asn_app_subscribers_blob_handler,
                                           ASN_APP_SUBSCRIBERS_BLOB_TYPE_event_users_invited,
                                           "event_users_invited");
  asn_set_blob_handler_for_name_with_type (&am->asn_main, asn_app_subscribers_blob_handler,
                                           ASN_APP_SUBSCRIBERS_BLOB_TYPE_event_groups_invited,
                                           "event_groups_invited");
  asn_set_blob_handler_for_name (&am->asn_main, asn_app_check_in_blob_handler, "checkins/*");

  if (! am->user_types[ASN_APP_USER_TYPE_user].user_type.was_registered)
    {
      asn_app_user_type_t t = {
        .user_type = {
          .name = "actual user",
          .user_type_n_bytes = sizeof (asn_app_user_t),
          .user_type_offset_of_asn_user = STRUCT_OFFSET_OF (asn_app_user_t, gen_user.asn_user),
          .free_user = asn_app_free_user,
          .serialize_pool_users = serialize_pool_asn_app_user,
          .unserialize_pool_users = unserialize_pool_asn_app_user,
        },
        .serialize_blob_contents = serialize_asn_app_profile_for_user,
        .unserialize_blob_contents = unserialize_asn_app_profile_for_user,
        .update_subscribers = asn_app_user_update_subscribers,
      };

      am->user_types[ASN_APP_USER_TYPE_user] = t;
      asn_register_user_type (&am->user_types[ASN_APP_USER_TYPE_user].user_type);
    }

  if (! am->user_types[ASN_APP_USER_TYPE_user_group].user_type.was_registered)
    {
      asn_app_user_type_t t = {
        .user_type = {
          .name = "user group",
          .user_type_n_bytes = sizeof (asn_app_user_group_t),
          .user_type_offset_of_asn_user = STRUCT_OFFSET_OF (asn_app_user_group_t, gen_user.asn_user),
          .free_user = asn_app_free_user_group,
          .serialize_pool_users = serialize_pool_asn_app_user_group,
          .unserialize_pool_users = unserialize_pool_asn_app_user_group,
        },
        .serialize_blob_contents = serialize_asn_app_profile_for_user_group,
        .unserialize_blob_contents = unserialize_asn_app_profile_for_user_group,
        .update_subscribers = asn_app_user_group_update_subscribers,
      };

      am->user_types[ASN_APP_USER_TYPE_user_group] = t;
      asn_register_user_type (&am->user_types[ASN_APP_USER_TYPE_user_group].user_type);
    }

  if (! am->user_types[ASN_APP_USER_TYPE_event].user_type.was_registered)
    {
      asn_app_user_type_t t = {
        .user_type = {
          .name = "event",
          .user_type_n_bytes = sizeof (asn_app_event_t),
          .user_type_offset_of_asn_user = STRUCT_OFFSET_OF (asn_app_event_t, gen_user.asn_user),
          .free_user = asn_app_free_event,
          .serialize_pool_users = serialize_pool_asn_app_event,
          .unserialize_pool_users = unserialize_pool_asn_app_event,
        },
        .serialize_blob_contents = serialize_asn_app_profile_for_event,
        .unserialize_blob_contents = unserialize_asn_app_profile_for_event,
        .update_subscribers = asn_app_event_update_subscribers,
      };

      am->user_types[ASN_APP_USER_TYPE_event] = t;
      asn_register_user_type (&am->user_types[ASN_APP_USER_TYPE_event].user_type);
    }

  if (! am->user_types[ASN_APP_USER_TYPE_place].user_type.was_registered)
    {
      asn_app_user_type_t t = {
        .user_type = {
          .name = "place",
          .user_type_n_bytes = sizeof (asn_app_place_t),
          .user_type_offset_of_asn_user = STRUCT_OFFSET_OF (asn_app_place_t, gen_user.asn_user),
          .free_user = asn_app_free_place,
          .serialize_pool_users = serialize_pool_asn_app_place,
          .unserialize_pool_users = unserialize_pool_asn_app_place,
        },
        .serialize_blob_contents = serialize_asn_app_profile_for_place,
        .unserialize_blob_contents = unserialize_asn_app_profile_for_place,
      };

      am->user_types[ASN_APP_USER_TYPE_place] = t;
      asn_register_user_type (&am->user_types[ASN_APP_USER_TYPE_place].user_type);
    }
}
