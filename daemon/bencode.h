#ifndef _BENCODE_H_
#define _BENCODE_H_

#include <sys/uio.h>
#include <string.h>

#if defined(PKG_MALLOC) || defined(pkg_malloc)
/* kamailio */
# include "../../mem/mem.h"
# include "../../str.h"
# ifndef BENCODE_MALLOC
# define BENCODE_MALLOC pkg_malloc
# define BENCODE_FREE pkg_free
# endif
#else
/* mediaproxy-ng */
# include "str.h"
# ifndef BENCODE_MALLOC
# define BENCODE_MALLOC malloc
# define BENCODE_FREE free
# endif
#endif

struct bencode_buffer;
enum bencode_type;
struct bencode_item;
struct __bencode_buffer_piece;
struct __bencode_free_list;

typedef enum bencode_type bencode_type_t;
typedef struct bencode_buffer bencode_buffer_t;
typedef struct bencode_item bencode_item_t;

enum bencode_type {
	BENCODE_INVALID = 0,
	BENCODE_STRING,		/* byte string */
	BENCODE_INTEGER,	/* long long int */
	BENCODE_LIST,		/* flat list of other objects */
	BENCODE_DICTIONARY,	/* dictionary of key/values pairs. keys are always strings */
	BENCODE_END_MARKER,	/* used internally only */
};

struct bencode_item {
	bencode_type_t type;
	struct iovec iov[2];	/* when decoding, iov[1] contains the contents of a string object */
	unsigned int iov_cnt;
	unsigned int str_len;	/* length of the whole ENCODED object. NOT the length of a byte string */
	long long int value;	/* when decoding an integer, contains the value */
	bencode_item_t *parent, *child, *sibling;
	bencode_buffer_t *buffer;
	char __buf[0];
};

struct bencode_buffer {
	struct __bencode_buffer_piece *pieces;
	struct __bencode_free_list *free_list;
};

/* Initializes a bencode_buffer_t object. This object is used to group together all memory allocations
 * made when encoding or decoding. Its memory usage is always growing, until it is freed, at which point
 * all objects created through it become invalid. The actual object must be allocated separately, for
 * example by being put on the stack.
 * Returns 0 on success or -1 on failure (if no memory could be allocated). */
int bencode_buffer_init(bencode_buffer_t *buf);

/* Destroys a previously initialized bencode_buffer_t object. All memory used by the object is freed
 * and all objects created through it become invalid. */
void bencode_buffer_free(bencode_buffer_t *buf);

/* Creates a new empty dictionary object. Memory will be allocated from the bencode_buffer_t object.
 * Returns NULL if no memory could be allocated. */
bencode_item_t *bencode_dictionary(bencode_buffer_t *buf);

/* Creates a new empty list object. Memory will be allocated from the bencode_buffer_t object.
 * Returns NULL if no memory could be allocated. */
bencode_item_t *bencode_list(bencode_buffer_t *buf);

/* Adds a pointer to the bencode_buffer_t object's internal free list. When the bencode_buffer_t
 * object is destroyed, BENCODE_FREE will be called on this pointer. */
void bencode_buffer_freelist_add(bencode_buffer_t *buf, void *);

/* Adds a new key/value pair to a dictionary. Memory will be allocated from the same bencode_buffer_t
 * object as the dictionary was allocated from. Returns NULL if no memory could be allocated, otherwise
 * returns "val".
 * The function does not check whether the key being added is already present in the dictionary.
 * Also, the function does not reorder keys into lexicographical order; keys will be encoded in
 * the same order as they've been added. The key must a null-terminated string.
 * The value to be added must not have been previously linked into any other dictionary or list. */
static inline bencode_item_t *bencode_dictionary_add(bencode_item_t *dict, const char *key, bencode_item_t *val);

/* Identical to bencode_dictionary_add() but doesn't require the key string to be null-terminated */
bencode_item_t *bencode_dictionary_add_len(bencode_item_t *dict, const char *key, int keylen, bencode_item_t *val);

/* Convenience function to add a string value to a dictionary */
static inline bencode_item_t *bencode_dictionary_add_string(bencode_item_t *dict, const char *key, const char *val);

/* Ditto, but for a "str" object */
static inline bencode_item_t *bencode_dictionary_add_str(bencode_item_t *dict, const char *key, const str *val);

/* Ditto again, but adds the str object (val) to the bencode_buffer_t's internal free list. When
 * the bencode_item_t object is destroyed, BENCODE_FREE will be called on this pointer. */
static inline bencode_item_t *bencode_dictionary_add_str_free(bencode_item_t *dict, const char *key, str *val);

/* Convenience function to add an integer value to a dictionary */
static inline bencode_item_t *bencode_dictionary_add_integer(bencode_item_t *dict, const char *key, long long int val);

/* Adds a new item to a list. Returns "item".
 * The item to be added must not have been previously linked into any other dictionary or list. */
bencode_item_t *bencode_list_add(bencode_item_t *list, bencode_item_t *item);

/* Convenience function to add a string item to a list */
static inline bencode_item_t *bencode_list_add_string(bencode_item_t *list, const char *s);

/* Creates a new byte-string object. The given string does not have to be null-terminated, instead
 * the length of the string is specified by the "len" parameter. Returns NULL if no memory could
 * be allocated.
 * Strings are not copied or duplicated, so the string pointed to by "s" must remain valid until
 * the complete document is finally encoded or sent out. */
bencode_item_t *bencode_string_len(bencode_buffer_t *buf, const char *s, int len);

/* Creates a new byte-string object. The given string must be null-terminated. Otherwise identical
 * to bencode_string_len(). */
static inline bencode_item_t *bencode_string(bencode_buffer_t *buf, const char *s);

/* Creates a new byte-string object from a "str" object. The string does not have to be null-
 * terminated. */
static inline bencode_item_t *bencode_str(bencode_buffer_t *buf, const str *s);

/* Creates a new integer object. Returns NULL if no memory could be allocated. */
bencode_item_t *bencode_integer(bencode_buffer_t *buf, long long int i);

/* Collapses and encodes the complete document structure under the "root" element (which normally
 * is either a dictionary or a list) into an array of "iovec" structures. This array can then be
 * passed to functions ala writev() or sendmsg() to output the encoded document as a whole. Memory
 * is allocated from the same bencode_buffer_t object as the "root" object was allocated from.
 * The "head" and "tail" parameters specify additional "iovec" structures that should be included
 * in the allocated array before or after (respectively) the iovec structures used by the encoded
 * document. Both parameters can be zero if no additional elements in the array are required.
 * Returns a pointer to the allocated array or NULL if no memory could be allocated. The number of
 * array elements is returned in "cnt" which must be a valid pointer to an int. This number does
 * not include any additional elements allocated through the "head" or "tail" parameters.
 *
 * Therefore, the contents of the returned array are:
 * [0 .. (head - 1)]                         = unused and uninitialized iovec structures
 * [(head) .. (head + cnt - 1)]              = the encoded document
 * [(head + cnt) .. (head + cnt + tail - 1)] = unused and uninitialized iovec structures
 *
 * The returned array will be freed when the corresponding bencode_buffer_t object is destroyed. */
struct iovec *bencode_iovec(bencode_item_t *root, int *cnt, unsigned int head, unsigned int tail);

/* Similar to bencode_iovec(), but instead returns the encoded document as a null-terminated string.
 * Memory for the string is allocated from the same bencode_buffer_t object as the "root" object
 * was allocated from. If "len" is a non-NULL pointer, the length of the genrated string is returned
 * in *len. This is important if the encoded document contains binary data, in which case null
 * termination cannot be trusted. The returned string is freed when the corresponding
 * bencode_buffer_t object is destroyed. */
char *bencode_collapse(bencode_item_t *root, int *len);

/* Identical to bencode_collapse() but fills in a "str" object. Returns "out". */
static str *bencode_collapse_str(bencode_item_t *root, str *out);

/* Identical to bencode_collapse(), but the memory for the returned string is not allocated from
 * a bencode_buffer_t object, but instead using the function defined as BENCODE_MALLOC (normally
 * malloc() or pkg_malloc()), similar to strdup(). Using this function, the bencode_buffer_t
 * object can be destroyed, but the returned string remains valid and usable. */
char *bencode_collapse_dup(bencode_item_t *root, int *len);

/* Decodes an encoded document from a string into a tree of bencode_item_t objects. The string does
 * not need to be null-terminated, instead the length of the string is given through the "len"
 * parameter. Memory is allocated from the bencode_buffer_t object. Returns NULL if no memory could
 * be allocated or if the document could not be successfully decoded.
 *
 * The returned element is the "root" of the document tree and normally is either a list object or
 * a dictionary object, but can also be a single string or integer object with no other objects
 * underneath or besides it (no childred and no siblings). The type of the object can be determined
 * by its ->type property.
 *
 * The number of bytes that could successfully be decoded into an object tree can be accessed through
 * the root element's ->str_len property. Normally, this number should be equal to the "len" parameter
 * passed, in which case the full string could be decoded. If ->str_len is less than "len", then there
 * was additional stray byte data after the end of the encoded document.
 *
 * The document tree can be traversed through the ->child and ->sibling pointers in each object. The
 * ->child pointer will be NULL for string and integer objects, as they don't contain other objects.
 * For lists and dictionaries, ->child will be a pointer to the LAST contained object. This last
 * contained object's ->sibling pointer will point to the last-but-one contained object of the list
 * or the dictionary, and so on. The FIRST contained element of a list of dictionary will have a
 * NULL ->sibling pointer.
 *
 * Lists are built in reverse and so traversing a list by following the ->sibling pointers will
 * traverse all the elements in reverse as well. This includes the ordering of key/value pairs in
 * dictionary: The first element in the list (where ->child points to) will be the VALUE of the LAST
 * key/value pair. The next element (following one ->sibling) will be the KEY of the LAST key/value
 * pair (guaranteed to be a string and guaranteed to be present). Following another ->sibling will
 * point to the VALUE of the last-but-one key/value pair, and so on.
 *
 * The decoding function for dictionary object does not check whether keys are unique within the
 * dictionary. It also does not care about lexicographical order of the keys.
 *
 * Decoded string objects will contain the raw decoded byte string in ->iov[1] (including the correct
 * length). Strings are NOT null-terminated. Decoded integer objects will contain the decoded value
 * in ->value.
 *
 * All memory is freed when the bencode_buffer_t object is destroyed.
 */
bencode_item_t *bencode_decode(bencode_buffer_t *buf, const char *s, int len);

/* Identical to bencode_decode(), but returns successfully only if the type of the decoded object match
 * "expect". */
static inline bencode_item_t *bencode_decode_expect(bencode_buffer_t *buf, const char *s, int len, bencode_type_t expect);

/* Identical to bencode_decode_expect() but takes a "str" argument. */
static inline bencode_item_t *bencode_decode_expect_str(bencode_buffer_t *buf, const str *s, bencode_type_t expect);

/* Searches the given dictionary object for the given key and returns the respective value. Returns
 * NULL if the given object isn't a dictionary or if the key doesn't exist. The key must be a
 * null-terminated string. */
static inline bencode_item_t *bencode_dictionary_get(bencode_item_t *dict, const char *key);

/* Identical to bencode_dictionary_get() but doesn't require the key to be null-terminated. */
bencode_item_t *bencode_dictionary_get_len(bencode_item_t *dict, const char *key, int key_len);

/* Identical to bencode_dictionary_get() but returns the value only if its type is a string, and
 * returns it as a pointer to the string itself. Returns NULL if the value is of some other type. The
 * returned string is NOT null-terminated. Length of the string is returned in *len, which must be a
 * valid pointer. The returned string will be valid until dict's bencode_buffer_t object is destroyed. */
static inline char *bencode_dictionary_get_string(bencode_item_t *dict, const char *key, int *len);

/* Identical to bencode_dictionary_get_string() but fills in a "str" struct. Returns str->s, which
 * may be NULL. */
static inline char *bencode_dictionary_get_str(bencode_item_t *dict, const char *key, str *str);

/* Identical to bencode_dictionary_get() but returns the string in a newly allocated buffer (using the
 * BENCODE_MALLOC function), which remains valid even after bencode_buffer_t is destroyed. */
static inline char *bencode_dictionary_get_string_dup(bencode_item_t *dict, const char *key, int *len);

/* Combines bencode_dictionary_get_str() and bencode_dictionary_get_string_dup(). Fills in a "str"
 * struct, but copies the string into a newly allocated buffer. Returns str->s. */
static inline char *bencode_dictionary_get_str_dup(bencode_item_t *dict, const char *key, str *str);

/* Identical to bencode_dictionary_get_string() but expects an integer object. The parameter "defval"
 * specified which value should be returned if the key is not found or if the value is not an integer. */
static inline long long int bencode_dictionary_get_integer(bencode_item_t *dict, const char *key, long long int defval);

/* Identical to bencode_dictionary_get(), but returns the object only if its type matches "expect". */
static inline bencode_item_t *bencode_dictionary_get_expect(bencode_item_t *dict, const char *key, bencode_type_t expect);


/**************************/

static inline bencode_item_t *bencode_string(bencode_buffer_t *buf, const char *s) {
	return bencode_string_len(buf, s, strlen(s));
}

static inline bencode_item_t *bencode_str(bencode_buffer_t *buf, const str *s) {
	return bencode_string_len(buf, s->s, s->len);
}

static inline bencode_item_t *bencode_dictionary_add(bencode_item_t *dict, const char *key, bencode_item_t *val) {
	if (!key)
		return NULL;
	return bencode_dictionary_add_len(dict, key, strlen(key), val);
}

static inline bencode_item_t *bencode_dictionary_add_string(bencode_item_t *dict, const char *key, const char *val) {
	if (!val)
		return NULL;
	return bencode_dictionary_add(dict, key, bencode_string(dict->buffer, val));
}

static inline bencode_item_t *bencode_dictionary_add_str(bencode_item_t *dict, const char *key, const str *val) {
	if (!val)
		return NULL;
	return bencode_dictionary_add(dict, key, bencode_str(dict->buffer, val));
}

static inline bencode_item_t *bencode_dictionary_add_str_free(bencode_item_t *dict, const char *key, str *val) {
	if (!val)
		return NULL;
	bencode_buffer_freelist_add(dict->buffer, val);
	return bencode_dictionary_add(dict, key, bencode_str(dict->buffer, val));
}

static inline bencode_item_t *bencode_dictionary_add_integer(bencode_item_t *dict, const char *key, long long int val) {
	return bencode_dictionary_add(dict, key, bencode_integer(dict->buffer, val));
}

static inline bencode_item_t *bencode_list_add_string(bencode_item_t *list, const char *s) {
	return bencode_list_add(list, bencode_string(list->buffer, s));
}

static inline bencode_item_t *bencode_dictionary_get(bencode_item_t *dict, const char *key) {
	if (!key)
		return NULL;
	return bencode_dictionary_get_len(dict, key, strlen(key));
}

static inline char *bencode_dictionary_get_string(bencode_item_t *dict, const char *key, int *len) {
	bencode_item_t *val;
	val = bencode_dictionary_get(dict, key);
	if (!val || val->type != BENCODE_STRING)
		return NULL;
	*len = val->iov[1].iov_len;
	return val->iov[1].iov_base;
}

static inline char *bencode_dictionary_get_str(bencode_item_t *dict, const char *key, str *str) {
	str->s = bencode_dictionary_get_string(dict, key, &str->len);
	if (!str->s)
		str->len = 0;
	return str->s;
}

static inline char *bencode_dictionary_get_string_dup(bencode_item_t *dict, const char *key, int *len) {
	const char *s;
	char *ret;
	s = bencode_dictionary_get_string(dict, key, len);
	if (!s)
		return NULL;
	ret = BENCODE_MALLOC(*len);
	if (!ret)
		return NULL;
	memcpy(ret, s, *len);
	return ret;
}

static inline char *bencode_dictionary_get_str_dup(bencode_item_t *dict, const char *key, str *str) {
	str->s = bencode_dictionary_get_string_dup(dict, key, &str->len);
	return str->s;
}

static inline long long int bencode_dictionary_get_integer(bencode_item_t *dict, const char *key, long long int defval) {
	bencode_item_t *val;
	val = bencode_dictionary_get(dict, key);
	if (!val || val->type != BENCODE_INTEGER)
		return defval;
	return val->value;
}

static inline bencode_item_t *bencode_decode_expect(bencode_buffer_t *buf, const char *s, int len, bencode_type_t expect) {
	bencode_item_t *ret;
	ret = bencode_decode(buf, s, len);
	if (!ret || ret->type != expect)
		return NULL;
	return ret;
}

static inline bencode_item_t *bencode_decode_expect_str(bencode_buffer_t *buf, const str *s, bencode_type_t expect) {
	return bencode_decode_expect(buf, s->s, s->len, expect);
}

static inline bencode_item_t *bencode_dictionary_get_expect(bencode_item_t *dict, const char *key, bencode_type_t expect) {
	bencode_item_t *ret;
	ret = bencode_dictionary_get(dict, key);
	if (!ret || ret->type != expect)
		return NULL;
	return ret;
}
static inline str *bencode_collapse_str(bencode_item_t *root, str *out) {
	out->s = bencode_collapse(root, &out->len);
	return out;
}

#endif
