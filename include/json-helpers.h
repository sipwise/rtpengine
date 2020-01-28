#ifndef __JSON_HELPERS_H__
#define __JSON_HELPERS_H__

#include <json-glib/json-glib.h>

#include "str.h"

/**
 * Retrieve a string value from a JSON object according to a key.
 * @param reader glib JsonReader that has the target object as its current node.
 * @param key name of the string value to retrieve
 * @return `str` string created from the string value, or `NULL` if no such value was found,
 *   the reader is in an error state or not pointing to a JSON object. Release using `free()`.
 */
str *json_reader_get_str(JsonReader *reader, const char *key);

/**
 * Retrieve a string value from a JSON object, using the JsonObject API, according to a key.
 * @param json glib JsonObject from which to get the string
 * @param key name of the string value to retrieve
 * @return `str` string created from the string value, or `NULL` if no such value was found,
 *   the reader is in an error state or not pointing to a JSON object. Release using `free()`.
 */
str *json_object_get_str(JsonObject *json, const char *key);

/**
 * Retrieve a string value from a JSON object, using the JsonObject API, according to a key, decoding the
 * URI encoded value. The resulting buffer might contain NULL values.
 * @param json glib JsonObject from which to get the string
 * @param key name of the string value to retrieve
 * @return `str` string created from the string value, or `NULL` if no such value was found,
 *   the reader is in an error state or not pointing to a JSON object. Release using `free()`.
 */
str *json_object_get_str_uri_enc(JsonObject *json, const char *key);

/**
 * Retrieve a string value from a JSON list, using the JsonArray API, according to a key.
 * @param json glib JsonArray from which to get the string
 * @param idx index to the string value to retrieve
 * @return `str` string created from the string value, or `NULL` if no such value was found,
 *   the reader is in an error state or not pointing to a JSON object. Release using `free()`.
 */
str *json_array_get_str(JsonArray *json, unsigned idx);

/**
 * Retrieve an integer value from a JSON object according to a key.
 * @param reader glib JsonReader that has the target object as its current node.
 * @param key name of the integer value to retrieve
 * @return integer value, if found, -1 otherwise.
 *   The widest possible "native" storage is used but depending on the original content, this might still result in data loss.
 */
long long json_reader_get_ll(JsonReader *reader, const char *key);

/**
 * Retrieve an integer value from a JSON object, using the JsonObject API, according to a key.
 * @param json glib JsonObject from which to get the integer
 * @param key name of the integer value to retrieve
 * @return integer value, if found, -1 otherwise.
 *   The widest possible "native" storage is used but depending on the original content, this might still result in data loss.
 */
long long json_object_get_ll(JsonObject *json, const char *key);

/**
 * Retrieve a string value from a JSON list according to an index.
 * This would also work on a JSON object, by retrieving values from keys ordered by storage order (but it is just weird).
 * @param reader glib JsonReader that has the target list as its current node
 * @param idx index to the string value to retrieve
 * @return `str` string created from the string value, or `NULL` if no such value was found,
 *   the reader is in an error state or not pointing to a JSON list or object. Release using `free()`.
 */
str *json_reader_get_str_element(JsonReader *reader, unsigned idx);

/**
 * Retrieve an integer value from a JSON list according to an index.
 * If the value is stored as a string, this call will run `strtoll` on it and return the result.
 * @param reader glib JsonReader that has the target list as its current node.
 * @param idx index to the string value to retrieve
 * @return integer value, if found, -1 otherwise.
 *   The widest possible "native" storage is used but depending on the original content, this might still result in data loss.
 */
long long json_reader_get_ll_element(JsonReader *reader, unsigned idx);

/**
 * Retrieve an integer value from a JSON list, using the JsonArray API according to an index.
 * If the value is stored as a string, this call will run `strtoll` on it and return the result.
 * @param json glib JsonArray from which to get the integer..
 * @param idx index to the string value to retrieve
 * @return integer value, if found, -1 otherwise.
 *   The widest possible "native" storage is used but depending on the original content, this might still result in data loss.
 */
long long json_array_get_ll(JsonArray *json, unsigned idx);

/**
 * Retrieve the current string value from a JSON reader and decode its URI encoding.
 * @param reader glib JsonReader whose current node is a string value
 * @return `str` string containing URI decoded value, or `NULL` if the reader is an error state, the current node is not
 *   a string value or the string value is not a valid URI encoded value. Release using `free()`.
 */
str *json_reader_get_string_value_uri_enc(JsonReader *reader);

/**
 * Retrieve a JSON node from a JSON object according to a key.
 * The node can be any node, but this call will be mostly useful to get an object or list to be fed into
 * `json_reader_new()`.
 * @param reader glib JsonReader that has the target object as its current node.
 * @param key name of the object or list value to retrieve
 * @return JSON node retrieved, if found, or `NULL` otherwise
 */
JsonNode *json_reader_get_node(JsonReader *reader, const char *key);

#endif /* __JSON_HELPERS_H__ */
