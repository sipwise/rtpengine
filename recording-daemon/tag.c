#include "tag.h"


// XXX copied from stream.c - unify?
tag_t *tag_get(metafile_t *mf, unsigned long id) {
	if (mf->tags->len <= id)
		g_ptr_array_set_size(mf->tags, id + 1);
	tag_t *ret = g_ptr_array_index(mf->tags, id);
	if (ret)
		goto out;

	ret = g_new0(tag_t, 1);
	g_ptr_array_index(mf->tags, id) = ret;

	ret->id = id;

out:
	return ret;
}

void tag_name(metafile_t *mf, unsigned long t, const char *s) {
	tag_t *tag = tag_get(mf, t);
	tag->name = g_string_chunk_insert(mf->gsc, s);
}

void tag_label(metafile_t *mf, unsigned long t, const char *s) {
	tag_t *tag = tag_get(mf, t);
	tag->label = g_string_chunk_insert(mf->gsc, s);
}

void tag_metadata(metafile_t *mf, unsigned long t, const char *s) {
	tag_t *tag = tag_get(mf, t);
	tag->metadata = g_string_chunk_insert(mf->gsc, s);
}

void tag_free(tag_t *tag) {
	g_free(tag);
}
