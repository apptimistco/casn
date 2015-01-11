#include <casn/asn_app.h>

#define foreach_siren_user_attribute            \
  _ (string, first_name)			\
  _ (string, last_name)				\
  _ (string, headline)				\
  _ (string, essay)				\
  _ (u32, birthday_in_days_since_jan_1970)	\
  _ (oneof_single_choice, ethnicity)		\
  _ (oneof_single_choice, gender)		\
  _ (oneof_single_choice, sexual_orientation)	\
  _ (oneof_single_choice, style)		\
  _ (oneof_multiple_choice, seeking)		\
  _ (oneof_multiple_choice, interested_in)

typedef enum {
#define _(type,name) SIREN_USER_ATTRIBUTE_##name,
  foreach_siren_user_attribute
#undef _
} siren_user_attribute_type_t;

#define foreach_siren_event_attribute           \
  _ (string, name)                              \
  _ (string, description)                       \
  _ (f64, start_time_stamp)                     \
  _ (u32, duration_in_minutes)                  \
  _ (oneof_multiple_choice, categories)

typedef enum {
#define _(type,name) SIREN_EVENT_ATTRIBUTE_##name,
  foreach_siren_event_attribute
#undef _
} siren_event_attribute_type_t;

#define foreach_siren_user_group_attribute      \
  _ (string, name)                              \
  _ (string, description)

typedef enum {
#define _(type,name) SIREN_USER_GROUP_ATTRIBUTE_##name,
  foreach_siren_user_group_attribute
#undef _
} siren_user_group_attribute_type_t;

static void siren_init_attributes (asn_app_main_t * am)
{
  u32 ai;

#define _(type,name)							\
  ai = asn_app_add_attribute (&am->user_attribute_main, ASN_APP_ATTRIBUTE_TYPE_##type, #name); \
  ASSERT (ai == SIREN_USER_ATTRIBUTE_##name);
  foreach_siren_user_attribute;
#undef _

#define _(type,name)							\
  ai = asn_app_add_attribute (&am->event_attribute_main, ASN_APP_ATTRIBUTE_TYPE_##type, #name); \
  ASSERT (ai == SIREN_EVENT_ATTRIBUTE_##name);
  foreach_siren_event_attribute;
#undef _

#define _(type,name)							\
  ai = asn_app_add_attribute (&am->user_group_attribute_main, ASN_APP_ATTRIBUTE_TYPE_##type, #name); \
  ASSERT (ai == SIREN_USER_GROUP_ATTRIBUTE_##name);
  foreach_siren_user_group_attribute;
#undef _
}

typedef struct {
  asn_app_photo_t * sample_user_photos;
  asn_app_photo_t * sample_event_photos;
  asn_app_main_t app_main;
  u32 * valid_user_indices;
} siren_test_main_t;

always_inline void
siren_test_main_free (siren_test_main_t * m)
{
  asn_app_photo_t * p;
  vec_foreach (p, m->sample_user_photos)
    asn_app_photo_free (p);
  vec_free (m->sample_user_photos);
  vec_foreach (p, m->sample_event_photos)
    asn_app_photo_free (p);
  vec_free (m->sample_event_photos);
  asn_app_main_free (&m->app_main);
  vec_free (m->valid_user_indices);
}

static u8 * format_random_lorem_ipsum_string (u8 * s, va_list * va)
{
  u32 * seed = va_arg (*va, u32 *);
  u32 min_copies = va_arg (*va, u32);
  u32 max_copies = va_arg (*va, u32);
  u32 n = min_copies + (max_copies > min_copies ? random_u32 (seed) % (max_copies - min_copies) : 0);
  u32 j;
  for (j = 0; j < n; j++)
    s = format (s, "%s%s",
                (j > 0 ? "  " : ""),
                "Lorem ipsum dolor sit amet, consectetur adipisicing elit,"
                " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.");
  return s;
}

static u8 * format_random_sentence (u8 * s, va_list * va)
{
  u32 * seed = va_arg (*va, u32 *);
  char * words[] = {
    "emerged", "as", "a", "figure", "in", "Hong Kong", "activist",
    "circles", "two", "years", "ago", "when", "he", "rallied", "students", "against", "a", "government",
    "plan", "to", "introduce", "patriotic", "education", "in", "schools", "attacking", "it", "as", "a",
    "means", "of", "chinese", "communist", "party", "indoctrination", "he", "played", "a", "pivotal", "role",
    "in", "setting", "off", "the", "demonstrations", "of", "the", "past", "week", "leading", "a", "surprise",
    "charge", "on", "a", "government", "building", "that", "resulted", "in", "his", "arrest", "and", "prompted",
    "thousands", "to", "take", "to", "the", "streets", "ahead", "of", "schedule", "local", "newspapers", "with",
    "close", "ties", "to", "beijing", "have", "sought", "to", "smear", "him", "as", "a", "tool", "of", "the",
    "united", "states",
  };
  int n_words = 8 + (random_u32 (seed) % 20);
  int i;
  for (i = 0; i < n_words; i++)
    s = format (s, "%s %s", (i > 0 ? "" : "The"), words[random_u32 (seed) % ARRAY_LEN (words)]);
  return s;
}

static u8 * format_random_description (u8 * s, va_list * va)
{
  u32 * seed = va_arg (*va, u32 *);
  u32 min_n_sentence = va_arg (*va, u32);
  u32 max_n_sentence = va_arg (*va, u32);
  u32 n = min_n_sentence + (max_n_sentence > min_n_sentence ? random_u32 (seed) % (max_n_sentence - min_n_sentence) : 0);
  u32 j;
  for (j = 0; j < n; j++)
    s = format (s, "%U.%s", format_random_sentence, seed, (j + 1 < n ? "  " : ""));
  return s;
}

static u8 * format_random_first_name (u8 * s, va_list * va)
{
  u32 * seed = va_arg (*va, u32 *);
  static char * t[] = { "Eliot", "Alex", "Bryan", "Rigel", "Felix", "Françoise", };
  return format (s, "%s", t[random_u32 (seed) % ARRAY_LEN (t)]);
}

static u8 * format_random_last_name (u8 * s, va_list * va)
{
  u32 * seed = va_arg (*va, u32 *);
  static char * t[] = { "Dresselhaus", "Chennault", "Alston", "Cable", "Ramos", "Chanut", };
  return format (s, "%s", t[random_u32 (seed) % ARRAY_LEN (t)]);
}

static u8 * format_random_headline (u8 * s, va_list * va)
{
  u32 * seed = va_arg (*va, u32 *);
  static char * t[] = {
        "Andy Warhol Is My Spirit Animal",
        "Jangling Paradigms Since 1978",
        "A Modern Gentlewomen",
        "Make Money Not War",
        "So, So Good.",
    };
  return format (s, "%s", t[random_u32 (seed) % ARRAY_LEN (t)]);
}

static void random_location (asn_app_location_t * l, u32 * seed, uword is_for_checkin)
{
  if (is_for_checkin && (random_u32 (seed) % 100) > 90)
    return;

  static char * d[] = {
    "Delfina",
    "Dolores Park",
    "Golden Gate Park Carousel",
    "The 500 Club",
  };
  static int oingoes;
  vec_add1 (l->address_lines, format (0, "%s %d", d[random_u32 (seed) % ARRAY_LEN (d)], oingoes));
  vec_add1 (l->address_lines, format (0, "San Francisco, CA"));
  l->unique_id = format (0, "%d", oingoes++);
}

static u8 * format_random_event_name (u8 * s, va_list * va)
{
  u32 * seed = va_arg (*va, u32 *);
  static char * d[] = {
    "Siren Launch Party",
    "Eliot's 50th Birthday Party",
    "Dinner Party at Rigel & Bryan's",
  };
  static int oingoes;
  return format (s, "%s %d", d[random_u32 (seed) % ARRAY_LEN (d)], oingoes++);
}

/* Find time stamp of start of current day. */
static f64 time_stamp_start_of_current_day ()
{
  time_t t_now = time (0);
  struct tm * tm_now = gmtime (&t_now);
  tm_now->tm_sec = tm_now->tm_min = tm_now->tm_hour = 0;
  return (f64) mktime (tm_now);
}

static f64 random_time_stamp (u32 * seed, u32 max_n_days, int in_future, u32 minute_units)
{
  f64 t_in_sec = time_stamp_start_of_current_day ();

  /* Add/subtract random number of days. */
  {  
    u32 d = random_u32 (seed) % (max_n_days + 1);
    t_in_sec += (in_future ? d : (-(d+1))) * 24*60*60;
  }

  /* Hour and minute. */
  t_in_sec += 60.*60. * (random_u32 (seed) % 24);
  t_in_sec += 60. * (random_u32 (seed) % (60 / minute_units)) * minute_units;

  return t_in_sec;
}

static u32 add_random_user (siren_test_main_t * tm, u32 * seed, u32 n_users, asn_app_position_on_earth_t * with_position)
{
  asn_app_main_t * am = &tm->app_main;
  asn_app_user_t * au;

  pool_get (am->user_pool, au);
  au->index = au - am->user_pool;
  vec_add1 (tm->valid_user_indices, au->index);

  au->position_on_earth = with_position[0];

  asn_app_attribute_t * as = am->user_attribute_main.attributes;

  asn_app_set_attribute (as + SIREN_USER_ATTRIBUTE_first_name, au->index, "%U", format_random_first_name, seed);
  asn_app_set_attribute (as + SIREN_USER_ATTRIBUTE_last_name, au->index, "%U", format_random_last_name, seed);
  asn_app_set_attribute (as + SIREN_USER_ATTRIBUTE_headline, au->index, "%U", format_random_headline, seed);
  asn_app_set_attribute (as + SIREN_USER_ATTRIBUTE_birthday_in_days_since_jan_1970, au->index,
                         time_stamp_start_of_current_day () - (18 + (random_u32 (seed) % 60))*365);
  asn_app_set_attribute (as + SIREN_USER_ATTRIBUTE_essay, au->index, "%U", format_random_description, seed, 3, 10);
  asn_app_set_oneof_attribute (as + SIREN_USER_ATTRIBUTE_gender, au->index,
                               random_u32 (seed) % 100 < 80 ? "Female" : "Male");
  asn_app_set_oneof_attribute (as + SIREN_USER_ATTRIBUTE_ethnicity, au->index,
                               random_u32 (seed) % 100 < 80 ? "Native American" : "Black");
  asn_app_set_oneof_attribute (as + SIREN_USER_ATTRIBUTE_sexual_orientation, au->index,
                               random_u32 (seed) % 100 < 80 ? "Queer" : "Straight");
  asn_app_set_oneof_attribute (as + SIREN_USER_ATTRIBUTE_style, au->index,
                               random_u32 (seed) % 100 < 50 ? "Minimalist Chic" : "Glam");
  
  {
    char * t[] = {
      "Friends",
      "Networking",
      "Romance",
      "Relationship",
      "Activity Partners",
      "Going Out Buddy",
      "Not Sure",
    };

    u32 mask = random_u32 (seed) & pow2_mask (ARRAY_LEN (t));
    u32 i;
    foreach_set_bit (i, mask, ({
      asn_app_set_oneof_attribute (as + SIREN_USER_ATTRIBUTE_seeking, au->index, t[i]);
    }));
  }

  {
    char * t[] = {
      "Animals",
      "Architecture",
      "Arts & Crafts",
      "Books/Literature",
      "Cars & Motorcycles",
      "Cocktails",
      "Design",
      "DIY/Making",
      "Education",
      "Fashion",
      "Feminism/Gender Studies",
      "Film",
      "Food & Cooking",
      "Gardening",
      "Hair & Beauty",
      "Health & Fitness",
      "History",
      "Home Decor",
      "Humor",
      "Music",
      "Nature",
      "Outdoor Activities",
      "Partying",
      "Photography",
      "Politics/Activism",
      "Science",
      "Sports",
      "Technology",
      "Travel",
      "Tattoos",
    };
    u32 mask = random_u32 (seed) & pow2_mask (ARRAY_LEN (t));
    u32 i, n_set = 0;
    foreach_set_bit (i, mask, ({
      asn_app_set_oneof_attribute (as + SIREN_USER_ATTRIBUTE_interested_in, au->index, t[i]);
      if (++n_set > 4) break;
    }));
  }

  if (au->index != 0)
    {
      int n_msgs = 2 + (random_u32 (seed) % 10);
      int i;
      for (i = 0; i < n_msgs; i++)
        {
          asn_app_message_union_t * m;
          vec_add2 (au->messages_by_increasing_time, m, 1);
          m->text.header.from_user_index = (random_u32 (seed) % 2) ? am->self_user_index : au->index;
          m->text.header.type = ASN_APP_MESSAGE_TYPE_text;
          m->text.header.time_stamp = random_time_stamp (seed, /* max days */ 7, /* in_future */ 0, /* minute_units */ 1);
          m->text.text = format (0, "%U", format_random_lorem_ipsum_string, seed, 5, 10);
        }
      vec_sort (au->messages_by_increasing_time, (void *) asn_app_sort_message_by_increasing_time);
    }

  {
    int n_locations = 2 + (random_u32 (seed) % 10);
    int i;
    for (i = 0; i < n_locations; i++)
      random_location (&au->recent_check_in_locations[au->recent_check_in_location_index++], seed, /* is_for_checkin */ 1);
  }

  {
    asn_app_photo_t * p;
    if (! tm->sample_event_photos)
      {
#include "t_image_data.h"
        vec_resize (tm->sample_event_photos, 5);
        vec_add (tm->sample_event_photos[0].thumbnail_as_image_data, p1_data, ARRAY_LEN (p1_data));
        vec_add (tm->sample_event_photos[1].thumbnail_as_image_data, p2_data, ARRAY_LEN (p2_data));
        vec_add (tm->sample_event_photos[2].thumbnail_as_image_data, p3_data, ARRAY_LEN (p3_data));
        vec_add (tm->sample_event_photos[3].thumbnail_as_image_data, p4_data, ARRAY_LEN (p4_data));
        vec_add (tm->sample_event_photos[4].thumbnail_as_image_data, p5_data, ARRAY_LEN (p5_data));
      }

    vec_add2 (au->photos, p, 1);
    p->thumbnail_as_image_data = vec_dup (tm->sample_event_photos[random_u32 (seed) % vec_len (tm->sample_event_photos)].thumbnail_as_image_data);
  }

  return au->index;
}

static void random_event_photo (siren_test_main_t * tm, asn_app_photo_t * p, u32 * seed)
{
  if (! tm->sample_event_photos)
    {
#include "e_image_data.h"
      vec_resize (tm->sample_event_photos, 4);
      vec_add (tm->sample_event_photos[0].thumbnail_as_image_data, p1_data, ARRAY_LEN (p1_data));
      vec_add (tm->sample_event_photos[1].thumbnail_as_image_data, p2_data, ARRAY_LEN (p2_data));
      vec_add (tm->sample_event_photos[2].thumbnail_as_image_data, p3_data, ARRAY_LEN (p3_data));
      vec_add (tm->sample_event_photos[3].thumbnail_as_image_data, p4_data, ARRAY_LEN (p4_data));
    }

  p->thumbnail_as_image_data = vec_dup (tm->sample_event_photos[random_u32 (seed) % vec_len (tm->sample_event_photos)].thumbnail_as_image_data);
 }

static u32 add_random_event (siren_test_main_t * tm, u32 * seed, asn_app_position_on_earth_t * with_position)
{
  asn_app_main_t * am = &tm->app_main;
  asn_app_event_t * e;

  pool_get (am->event_pool, e);
  e->index = e - am->event_pool;

  e->position_on_earth = with_position[0];

  asn_app_attribute_t * as = am->event_attribute_main.attributes;

  asn_app_set_attribute (as + SIREN_EVENT_ATTRIBUTE_name, e->index,
                         "%U", format_random_event_name, seed);
  asn_app_set_attribute (as + SIREN_EVENT_ATTRIBUTE_description, e->index,
                         "%U", format_random_description, seed, 2, 10);

  asn_app_set_attribute (as + SIREN_EVENT_ATTRIBUTE_start_time_stamp, e->index,
                         random_time_stamp (seed, 7, /* in_future */ 1, 15));
  asn_app_set_attribute (as + SIREN_EVENT_ATTRIBUTE_duration_in_minutes,
                         15 * (1 + (random_u32 (seed) % 10)));

  {
    char * t[] = {
      "Category 1", "Category 2", "Category 3", "Category 4", "Category 5",
    };
    u32 mask = random_u32 (seed) & pow2_mask (ARRAY_LEN (t));
    u32 i, n_set = 0;
    foreach_set_bit (i, mask, ({
      asn_app_set_oneof_attribute (as + SIREN_EVENT_ATTRIBUTE_categories, e->index, t[i]);
      if (++n_set > 4) break;
    }));
  }

  e->is_private = random_u32 (seed) & 1;
  e->is_created_by_self_user = 1;

  {
    int n_msgs = 2 + (random_u32 (seed) % 10);
    int i;
    for (i = 0; i < n_msgs; i++)
      {
        asn_app_message_union_t * m;
        vec_add2 (e->messages_by_increasing_time, m, 1);
        m->text.header.from_user_index = tm->valid_user_indices[random_u32 (seed) % vec_len (tm->valid_user_indices)];
        m->text.header.type = ASN_APP_MESSAGE_TYPE_text;
        m->text.header.time_stamp = random_time_stamp (seed, /* max days */ 7, /* in_future */ 0, /* minute_units */ 1);
        m->text.text = format (0, "%U", format_random_lorem_ipsum_string, seed, 1, 3);
      }
    vec_sort (e->messages_by_increasing_time, (void *) asn_app_sort_message_by_increasing_time);
  }

  {
    asn_app_photo_t * p;
    vec_add2 (e->photos, p, 1);
    random_event_photo (tm, p, seed);
  }

  return e->index;
}

static u8 * format_random_group_name (u8 * s, va_list * va)
{
  u32 * seed = va_arg (*va, u32 *);
  static char * t[] = {
    "Bay Area Entrepreneurs",
    "Sunday Supper Club",
  };
  static int oingoes = 1;
  return format (s, "%s %d", t[random_u32 (seed) % ARRAY_LEN (t)], oingoes++);
}

static u32 add_random_group (siren_test_main_t * tm, u32 * seed)
{
  asn_app_main_t * am = &tm->app_main;
  asn_app_user_group_t * g;
  asn_app_attribute_t * as = am->user_group_attribute_main.attributes;
  uword * group_member_bitmap = clib_bitmap_ori (0, am->self_user_index);

  pool_get (am->user_group_pool, g);
  g->index = g - am->user_group_pool;

  asn_app_set_attribute (as + SIREN_USER_GROUP_ATTRIBUTE_name, g->index,
                         "%U", format_random_group_name, seed);
  asn_app_set_attribute (as + SIREN_USER_GROUP_ATTRIBUTE_description, g->index,
                         "%U", format_random_description, seed, 1, 5);

  {
    int n_msgs = 2 + (random_u32 (seed) % 10);
    int i;
    for (i = 0; i < n_msgs; i++)
      {
        asn_app_message_union_t * m;
        vec_add2 (g->messages_by_increasing_time, m, 1);
        m->text.header.from_user_index = tm->valid_user_indices[random_u32 (seed) % vec_len (tm->valid_user_indices)];
        group_member_bitmap = clib_bitmap_ori (group_member_bitmap, m->text.header.from_user_index);
        m->text.header.type = ASN_APP_MESSAGE_TYPE_text;
        m->text.header.time_stamp = random_time_stamp (seed, /* max days */ 7, /* in_future */ 0, /* minute_units */ 1);
        m->text.text = format (0, "%U", format_random_lorem_ipsum_string, seed, 1, 3);
      }
    vec_sort (g->messages_by_increasing_time, (void *) asn_app_sort_message_by_increasing_time);
  }

  {
    uword i;
    g->group_users = hash_create (0, /* value_bytes */ 0);
    clib_bitmap_foreach (i, group_member_bitmap, ({
      hash_set1 (g->group_users, i);
    }));
    clib_bitmap_free (group_member_bitmap);
  }

  {
    asn_app_photo_t * p;
    vec_add2 (g->photos, p, 1);
    random_event_photo (tm, p, seed);
  }

  return g->index;
}

int main (int argc, char * argv[])
{
  siren_test_main_t _tm = {0}, * tm = &_tm;
  asn_app_main_t * am = &tm->app_main;
  u32 seed = 0;

  clib_mem_init (0, 256 << 20);

  clib_warning ("%U", format_clib_mem_usage, /* verbose */ 0);

  siren_init_attributes (am);

  {
    int i, n = 100;
    asn_app_position_on_earth_t pos = { .longitude = 0, .latitude = 0, };
    for (i = 0; i < n; i++)
      add_random_user (tm, &seed, n, &pos);

    for (i = 0; i < 100; i++)
      add_random_event (tm, &seed, &pos);

    for (i = 0; i < 10; i++)
      add_random_group (tm, &seed);
  }

  clib_warning ("%U", format_clib_mem_usage, /* verbose */ 0);

  {
    clib_error_t * error = asn_app_main_write_to_file (am, "fart");
    if (error)
      clib_error_report (error);
  }

  siren_test_main_free (tm);

  clib_warning ("%U", format_clib_mem_usage, /* verbose */ 0);

  siren_init_attributes (am);

  {
    clib_error_t * error = asn_app_main_read_from_file (am, "fart");
    if (error)
      clib_error_report (error);

    siren_test_main_free (tm);
    clib_warning ("%U", format_clib_mem_usage, /* verbose */ 0);
  }

  return 0;
}

