#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "bencode.h"

/* set to 0 for alloc debugging, e.g. through valgrind */
#define BENCODE_MIN_BUFFER_PIECE_LEN	512

struct __bencode_buffer_piece {
	char *tail;
	unsigned int left;
	struct __bencode_buffer_piece *next;
	char buf[0];
};
struct __bencode_free_list {
	void *ptr;
	struct __bencode_free_list *next;
};





static bencode_item_t __bencode_end_marker = {
	.type = BENCODE_END_MARKER,
	.iov[0].iov_base = "e",
	.iov[0].iov_len = 1,
	.iov_cnt = 1,
	.str_len = 1,
};




static bencode_item_t *__bencode_decode(bencode_buffer_t *buf, const char *s, const char *end);



static void __bencode_item_init(bencode_item_t *item) {
	item->parent = item->child = item->sibling = NULL;
}

static void __bencode_container_init(bencode_item_t *cont) {
	cont->iov[0].iov_len = 1;
	cont->iov[1].iov_base = "e";
	cont->iov[1].iov_len = 1;
	cont->iov_cnt = 2;
	cont->str_len = 2;
}

static void bencode_dictionary_init(bencode_item_t *dict) {
	dict->type = BENCODE_DICTIONARY;
	dict->iov[0].iov_base = "d";
	__bencode_container_init(dict);
}

static void bencode_list_init(bencode_item_t *list) {
	list->type = BENCODE_LIST;
	list->iov[0].iov_base = "l";
	__bencode_container_init(list);
}

static struct __bencode_buffer_piece *__bencode_piece_new(unsigned int size) {
	struct __bencode_buffer_piece *ret;

	if (size < BENCODE_MIN_BUFFER_PIECE_LEN)
		size = BENCODE_MIN_BUFFER_PIECE_LEN;
	ret = BENCODE_MALLOC(sizeof(*ret) + size);
	if (!ret)
		return NULL;

	ret->tail = ret->buf;
	ret->left = size;
	ret->next = NULL;

	return ret;
}

int bencode_buffer_init(bencode_buffer_t *buf) {
	buf->pieces = __bencode_piece_new(0);
	if (!buf->pieces)
		return -1;
	return 0;
}

static void *__bencode_alloc(bencode_buffer_t *buf, unsigned int size) {
	struct __bencode_buffer_piece *piece;
	void *ret;

	piece = buf->pieces;

	if (size <= piece->left)
		goto alloc;

	piece = __bencode_piece_new(size);
	if (!piece)
		return NULL;
	piece->next = buf->pieces;
	buf->pieces = piece;

	assert(size <= piece->left);

alloc:
	piece->left -= size;
	ret = piece->tail;
	piece->tail += size;
	return ret;
}

void bencode_buffer_free(bencode_buffer_t *buf) {
	struct __bencode_free_list *fl;
	struct __bencode_buffer_piece *piece, *next;

	for (fl = buf->free_list; fl; fl = fl->next)
		BENCODE_FREE(fl->ptr);

	for (piece = buf->pieces; piece; piece = next) {
		next = piece->next;
		BENCODE_FREE(piece);
	}
}

static bencode_item_t *__bencode_item_alloc(bencode_buffer_t *buf, unsigned int payload) {
	bencode_item_t *ret;

	ret = __bencode_alloc(buf, sizeof(struct bencode_item) + payload);
	if (!ret)
		return NULL;
	ret->buffer = buf;
	__bencode_item_init(ret);
	return ret;
}

bencode_item_t *bencode_dictionary(bencode_buffer_t *buf) {
	bencode_item_t *ret;

	ret = __bencode_item_alloc(buf, 0);
	if (!ret)
		return NULL;
	bencode_dictionary_init(ret);
	return ret;
}

bencode_item_t *bencode_list(bencode_buffer_t *buf) {
	bencode_item_t *ret;

	ret = __bencode_item_alloc(buf, 0);
	if (!ret)
		return NULL;
	bencode_list_init(ret);
	return ret;
}

static void __bencode_container_add(bencode_item_t *parent, bencode_item_t *child) {
	assert(child->parent == NULL);
	assert(child->sibling == NULL);

	child->parent = parent;
	child->sibling = parent->child;
	parent->child = child;

	while (parent) {
		parent->iov_cnt += child->iov_cnt;
		parent->str_len += child->str_len;
		parent = parent->parent;
	}
}

bencode_item_t *bencode_string_len(bencode_buffer_t *buf, const char *s, int len) {
	bencode_item_t *ret;
	int len_len;

	assert((len <= 99999) && (len >= 0));
	ret = __bencode_item_alloc(buf, strlen(s) + 7);
	if (!ret)
		return NULL;
	len_len = sprintf(ret->__buf, "%d:", len);

	ret->type = BENCODE_STRING;
	ret->iov[0].iov_base = ret->__buf;
	ret->iov[0].iov_len = len_len;
	ret->iov[1].iov_base = (void *) s;
	ret->iov[1].iov_len = len;
	ret->iov_cnt = 2;
	ret->str_len = len_len + len;

	return ret;
}

bencode_item_t *bencode_integer(bencode_buffer_t *buf, long long int i) {
	bencode_item_t *ret;
	int alen, rlen;

	alen = 8;
	while (1) {
		ret = __bencode_item_alloc(buf, alen + 3);
		if (!ret)
			return NULL;
		rlen = snprintf(ret->__buf, alen, "i%llde", i);
		if (rlen < alen)
			break;
		alen <<= 1;
	}

	ret->type = BENCODE_INTEGER;
	ret->iov[0].iov_base = ret->__buf;
	ret->iov[0].iov_len = rlen;
	ret->iov[1].iov_base = NULL;
	ret->iov[1].iov_len = 0;
	ret->iov_cnt = 1;
	ret->str_len = rlen;

	return ret;
}

bencode_item_t *bencode_dictionary_add_len(bencode_item_t *dict, const char *key, int keylen, bencode_item_t *val) {
	bencode_item_t *str;

	assert(dict->type == BENCODE_DICTIONARY);
	if (!val)
		return NULL;

	str = bencode_string_len(dict->buffer, key, keylen);
	if (!str)
		return NULL;
	__bencode_container_add(dict, str);
	__bencode_container_add(dict, val);
	return val;
}

bencode_item_t *bencode_list_add(bencode_item_t *list, bencode_item_t *item) {
	assert(list->type == BENCODE_LIST);
	__bencode_container_add(list, item);
	return item;
}

static int __bencode_iovec_dump_rev(struct iovec *out, bencode_item_t *item) {
	bencode_item_t *child;
	struct iovec *orig = out;

	if (item->iov[1].iov_base)
		*--out = item->iov[1];

	child = item->child;
	while (child) {
		out -= __bencode_iovec_dump_rev(out, child);
		child = child->sibling;
	}

	assert(item->iov[0].iov_base != NULL);
	*--out = item->iov[0];

	assert((orig - out) == item->iov_cnt);
	return item->iov_cnt;
}

static int __bencode_str_dump_rev(char *out, bencode_item_t *item) {
	bencode_item_t *child;
	char *orig = out;

	if (item->iov[1].iov_base) {
		out -= item->iov[1].iov_len;
		memcpy(out, item->iov[1].iov_base, item->iov[1].iov_len);
	}

	child = item->child;
	while (child) {
		out -= __bencode_str_dump_rev(out, child);
		child = child->sibling;
	}

	assert(item->iov[0].iov_base != NULL);
	out -= item->iov[0].iov_len;
	memcpy(out, item->iov[0].iov_base, item->iov[0].iov_len);

	assert((orig - out) == item->str_len);
	return item->str_len;
}

static int __bencode_iovec_dump(struct iovec *out, bencode_item_t *item) {
	int len;

	/* sibling lists are built in reverse, so dump everything
	   out backwards, end to start */
	out += item->iov_cnt;
	len = __bencode_iovec_dump_rev(out, item);
	assert(len == item->iov_cnt);
	return len;
}

static int __bencode_str_dump(char *out, bencode_item_t *item) { 
	int len;
	char *orig = out;

	/* sibling lists are built in reverse, so dump everything
	   out backwards, end to start */
	out += item->str_len;
	len = __bencode_str_dump_rev(out, item);
	assert(len == item->str_len);
	orig[len] = '\0';
	return len;
}

struct iovec *bencode_iovec(bencode_item_t *root, int *cnt, unsigned int head, unsigned int tail) {
	struct iovec *ret;

	assert(root != NULL);
	assert(cnt != NULL);
	assert(root->iov_cnt > 0);

	ret = __bencode_alloc(root->buffer, sizeof(*ret) * (root->iov_cnt + head + tail));
	if (!ret)
		return NULL;
	*cnt = __bencode_iovec_dump(ret + head, root);
	return ret;
}

char *bencode_collapse(bencode_item_t *root, int *len) {
	char *ret;
	int l;

	assert(root != NULL);
	assert(root->str_len > 0);

	ret = __bencode_alloc(root->buffer, root->str_len + 1);
	if (!ret)
		return NULL;
	l = __bencode_str_dump(ret, root);
	if (len)
		*len = l;
	return ret;
}

char *bencode_collapse_dup(bencode_item_t *root, int *len) {
	char *ret;
	int l;

	assert(root != NULL);
	assert(root->str_len > 0);

	ret = BENCODE_MALLOC(root->str_len + 1);
	if (!ret)
		return NULL;

	l = __bencode_str_dump(ret, root);
	if (len)
		*len = l;
	return ret;
}

static bencode_item_t *bencode_decode_dictionary(bencode_buffer_t *buf, const char *s, const char *end) {
	bencode_item_t *ret, *item;

	if (*s != 'd')
		return NULL;
	s++;

	ret = __bencode_item_alloc(buf, 0);
	if (!ret)
		return NULL;
	bencode_dictionary_init(ret);

	while (s < end) {
		item = __bencode_decode(buf, s, end);
		if (!item)
			return NULL;
		s += item->str_len;
		if (item->type == BENCODE_END_MARKER)
			break;
		if (item->type != BENCODE_STRING)
			return NULL;
		__bencode_container_add(ret, item);

		if (s >= end)
			return NULL;
		item = __bencode_decode(buf, s, end);
		if (!item)
			return NULL;
		s += item->str_len;
		if (item->type == BENCODE_END_MARKER)
			return NULL;
		__bencode_container_add(ret, item);
	}

	return ret;
}

static bencode_item_t *bencode_decode_list(bencode_buffer_t *buf, const char *s, const char *end) {
	bencode_item_t *ret, *item;

	if (*s != 'l')
		return NULL;
	s++;

	ret = __bencode_item_alloc(buf, 0);
	if (!ret)
		return NULL;
	bencode_list_init(ret);

	while (s < end) {
		item = __bencode_decode(buf, s, end);
		if (!item)
			return NULL;
		s += item->str_len;
		if (item->type == BENCODE_END_MARKER)
			break;
		__bencode_container_add(ret, item);
	}

	return ret;
}

static bencode_item_t *bencode_decode_integer(bencode_buffer_t *buf, const char *s, const char *end) {
	long long int i;
	const char *orig = s;
	char *convend;
	bencode_item_t *ret;

	if (*s != 'i')
		return NULL;
	s++;

	if (s >= end)
		return NULL;

	if (*s == '0') {
		i = 0;
		s++;
		goto done;
	}

	i = strtoll(s, &convend, 10);
	if (convend == s)
		return NULL;
	s += (convend - s);

done:
	if (s >= end)
		return NULL;
	if (*s != 'e')
		return NULL;
	s++;

	ret = __bencode_item_alloc(buf, 0);
	if (!ret)
		return NULL;
	ret->type = BENCODE_INTEGER;
	ret->iov[0].iov_base = (void *) orig;
	ret->iov[0].iov_len = s - orig;
	ret->iov[1].iov_base = NULL;
	ret->iov[1].iov_len = 0;
	ret->iov_cnt = 1;
	ret->str_len = s - orig;
	ret->value = i;

	return ret;
}

static bencode_item_t *bencode_decode_string(bencode_buffer_t *buf, const char *s, const char *end) {
	unsigned long int sl;
	char *convend;
	const char *orig = s;
	bencode_item_t *ret;

	if (*s == '0') {
		sl = 0;
		s++;
		goto colon;
	}

	sl = strtoul(s, &convend, 10);
	if (convend == s)
		return NULL;
	s += (convend - s);

colon:
	if (s >= end)
		return NULL;
	if (*s != ':')
		return NULL;
	s++;

	if (s + sl > end)
		return NULL;

	ret = __bencode_item_alloc(buf, 0);
	if (!ret)
		return NULL;
	ret->type = BENCODE_STRING;
	ret->iov[0].iov_base = (void *) orig;
	ret->iov[0].iov_len = s - orig;
	ret->iov[1].iov_base = (void *) s;
	ret->iov[1].iov_len = sl;
	ret->iov_cnt = 2;
	ret->str_len = s - orig + sl;

	return ret;
}

static bencode_item_t *__bencode_decode(bencode_buffer_t *buf, const char *s, const char *end) {
	if (s >= end)
		return NULL;

	switch (*s) {
		case 'd':
			return bencode_decode_dictionary(buf, s, end);
		case 'l':
			return bencode_decode_list(buf, s, end);
		case 'i':
			return bencode_decode_integer(buf, s, end);
		case 'e':
			return &__bencode_end_marker;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			return bencode_decode_string(buf, s, end);
		default:
			return NULL;
	}
}

bencode_item_t *bencode_decode(bencode_buffer_t *buf, const char *s, int len) {
	assert(s != NULL);
	return __bencode_decode(buf, s, s + len);
}


/* XXX inefficient, use a proper hash instead */
bencode_item_t *bencode_dictionary_get_len(bencode_item_t *dict, const char *keystr, int keylen) {
	bencode_item_t *key, *val;

	if (!dict)
		return NULL;
	if (dict->type != BENCODE_DICTIONARY)
		return NULL;

	for (val = dict->child; val; val = key->sibling) {
		key = val->sibling;
		assert(key != NULL);
		assert(key->type == BENCODE_STRING);

		if (keylen != key->iov[1].iov_len)
			continue;
		if (memcmp(keystr, key->iov[1].iov_base, keylen))
			continue;

		return val;
	}

	return NULL;
}

void bencode_buffer_freelist_add(bencode_buffer_t *buf, void *p) {
	struct __bencode_free_list *li;

	if (!p)
		return;
	li = __bencode_alloc(buf, sizeof(*li));
	if (!li)
		return;
	li->ptr = p;
	li->next = buf->free_list;
	buf->free_list = li;
}
