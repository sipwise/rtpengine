#include "json-helpers.h"

/**
 * Helper method to create `str` instances from C-strings that glib uses often
 * @param c C-style string where `strlen()` reports correct length.
 * @return `str` string. Release using `free()`.
 */
static str *str_dup_charptr(const char *c) {
	str temp = { .s = (char*)c, .len = strlen(c) };
	return str_dup(&temp);
}

/**
 * Helper method to test if the current node the reader is pointing to is a string value.
 * Similar to `json_reader_is_value()` but will only return non-zero for values that are string values.
 * @param reader JSON reader that is not in an error state
 * @return non-zero if the current node is a string value and the reader is not in an error state. zero otherwise.
 */
static int json_reader_is_string(JsonReader* reader) {
	JsonNode *node;

	node = json_reader_get_value(reader);
	if (json_node_get_value_type(node) == G_TYPE_STRING)
		return 1;
	return 0;
}

str *json_reader_get_str(JsonReader *reader, const char *key) {
	const gchar *strval;
	str *out = NULL;
	json_reader_read_member(reader, key);
	strval = json_reader_get_string_value(reader);
	json_reader_end_member(reader);
	if (strval)
		out = str_dup_charptr(strval);
	return out;
}

str *json_reader_get_str_element(JsonReader *reader, unsigned idx) {
	const gchar *strval = NULL;
	str *out = NULL;
	json_reader_read_element(reader, idx);
	strval = json_reader_get_string_value(reader);
	json_reader_end_element(reader);
	if (strval)
		out = str_dup_charptr(strval);
	return out;
}

long long json_reader_get_ll_element(JsonReader *reader, unsigned idx) {
	str *strval;
	long long out = -1;
	if (json_reader_read_element(reader, idx)) {
		if (json_reader_is_string(reader)) {
			json_reader_end_element(reader);
			strval = json_reader_get_str_element(reader, idx);
			if (strval) {
				out = strtoll(strval->s, NULL, 10);
				free(strval);
			}
		} else {
			out = json_reader_get_int_value(reader);
			json_reader_end_element(reader);
		}
	} else
		json_reader_end_element(reader);
	return out;
}

str *json_reader_get_string_value_uri_enc(JsonReader *reader) {
	const char *s = json_reader_get_string_value(reader);
	if (!s)
		return NULL;
	str *out = str_uri_decode_len(s, strlen(s));
	return out;
}

long long json_reader_get_ll(JsonReader *reader, const char *key) {
	long long r = -1;

	if (!json_reader_read_member(reader, key)) {
		json_reader_end_member(reader);
		return r;
	}
	if (json_reader_is_string(reader)) {
		str *ret = json_reader_get_string_value_uri_enc(reader);
		json_reader_end_member(reader);
		r = strtoll(ret->s, NULL, 10);
		free(ret);
		return r;
	}
	/* not a string, lets assume integer */
	r = json_reader_get_int_value(reader);
	json_reader_end_member(reader);
	return r;
}

JsonNode* json_reader_get_node(JsonReader *reader, const char *key) {
	JsonNode* nodeval;
	json_reader_read_member(reader, key);
	nodeval = json_reader_get_value(reader);
	json_reader_end_member(reader);
	return nodeval;
}
