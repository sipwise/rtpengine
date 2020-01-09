#ifndef __JSON_HELPERS_H__
#define __JSON_HELPERS_H__

#include <json-glib/json-glib.h>

#include "str.h"

/**
 * Retrieve a string value from a JSON object (in the root of the reader) according to a key.
 * @param reader glib JsonReader that has the target object as its current node.
 * @param key name of the string value to retrieve
 * @return `str` string created from the string value, or `NULL` if no such value was found,
 *   the reader is in an error state or not pointing to a JSON object. Release using `free()`.
 */
str* json_reader_get_str(JsonReader *reader, const char *key);

/**
 * Retrieve an integer value from a JSON object (in the root of the reader) according to a key.
 * @param reader glib JsonReader that has the target object as its current node.
 * @param key name of the integer value to retrieve
 * @return integer value, if found, -1 otherwise.
 *   The widest possible "native" storage is used but depending on the original content, this might still result in data loss.
 */
long long json_reader_get_ll(JsonReader *reader, const char *key);

/**
 * Retrieve a string value from a JSON list (in the root of the reader) according to an index.
 * This would also work on a JSON object, by retrieving values from keys ordered by storage order (but it is just weird).
 * @param reader glib JsonReader that has the target list as its current node.
 * @param idx index to the string value to retrieve
 * @return `str` string created from the string value, or `NULL` if no such value was found,
 *   the reader is in an error state or not pointing to a JSON list or object. Release using `free()`.
 */
str* json_reader_get_str_element(JsonReader *reader, unsigned idx);

/**
 * Retrieve an integer value from a JSON list (in the root of the reader) according to an index.
 * If the value is stored as a string, this call will run `strtoll` on it and return the result.
 * @param reader glib JsonReader that has the target list as its current node.
 * @param idx index to the string value to retrieve
 * @return integer value, if found, -1 otherwise.
 *   The widest possible "native" storage is used but depending on the original content, this might still result in data loss.
 */
long long json_reader_get_ll_element(JsonReader *reader, unsigned idx);

/**
 * Retrieve the current string value from a JSON reader and decode its URI encoding.
 * @param reader glib JsonReader whose current node is a string value
 * @return `str` string containing URI decoded value, or `NULL` if the reader is an error state, the current node is not
 *   a string value or the string value is not a valid URI encoded value. Release using `free()`.
 */
str *json_reader_get_string_value_uri_enc(JsonReader *reader);

#endif /* __JSON_HELPERS_H__ */
