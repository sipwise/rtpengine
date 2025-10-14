static int extmap_find(const void *key, const void *ele) {
	const uint8_t *k = key, *e = ele;
	if (*k < *e)
		return -1;
	if (*k > *e)
		return 1;
	return 0;
}

static bool extmap_has_ext(uint8_t id, struct rtpengine_output *o) {
	uint8_t const *match = bsearch(&id, o->output.extmap_filter, o->output.num_extmap_filter,
			sizeof(*o->output.extmap_filter), extmap_find);
	return match != NULL;
}

static bool apply_extmap_filter_ext(uint8_t id, size_t len, size_t size,
		unsigned char **r, unsigned char **w, unsigned char *end,
		unsigned int *count,
		struct rtpengine_output *o)
{
	if (*r + size + len > end)
		return false;

	if (extmap_has_ext(id, o)) {
		// retain ext
		if (*r != *w)
			memmove(*w, *r, len + size);
		*w += len + size;
		(*count)++;
	}
	// else: skip over & filter out

	*r += len + size;

	return true;
}

static unsigned char *insert_skb_data(unsigned char **w, struct sk_buff *skb, struct rtp_parsed *rtp,
		unsigned int len)
{
	unsigned char *ret = *w;
	unsigned char *end = ret + len;
	if (end > rtp->payload) {
		size_t put = end - rtp->payload;
		skb_put(skb, put);
		memmove(rtp->payload + put, rtp->payload, rtp->payload_len);
		rtp->payload += put;
	}
	(*w) += len;
	return ret;
}

static void add_extmap_ext_short(unsigned char **w, unsigned int *count,
		struct sk_buff *skb, struct rtp_parsed *rtp, uint8_t id, uint8_t len, char *content)
{
	unsigned char *wp = insert_skb_data(w, skb, rtp, 1 + len);
	*wp++ = (id << 4) | ((len - 1) & 0xf);
	memcpy(wp, content, len);

	(*count)++;
}
static void add_extmap_ext_long(unsigned char **w, unsigned int *count,
		struct sk_buff *skb, struct rtp_parsed *rtp, uint8_t id, uint8_t len, char *content)
{
	unsigned char *wp = insert_skb_data(w, skb, rtp, 2 + len);
	*wp++ = id;
	*wp++ = len;
	memcpy(wp, content, len);

	(*count)++;
}

static void add_extmap_exts_short(unsigned char **w, unsigned int *count,
		struct rtpengine_output *o, struct rtp_parsed *rtp, struct sk_buff *skb)
{
	if (!o->output.extmap_mid)
		return;
	add_extmap_ext_short(w, count, skb, rtp, o->output.extmap_mid, o->output.extmap_mid_len,
			o->output.extmap_mid_str);
}
static void add_extmap_exts_long(unsigned char **w, unsigned int *count,
		struct rtpengine_output *o, struct rtp_parsed *rtp, struct sk_buff *skb)
{
	if (!o->output.extmap_mid)
		return;
	add_extmap_ext_long(w, count, skb, rtp, o->output.extmap_mid, o->output.extmap_mid_len,
			o->output.extmap_mid_str);
}

static void apply_extmap_filter_finish(unsigned char *r, unsigned char *w, unsigned int count,
		struct rtpengine_output *o, struct sk_buff *skb, struct rtp_parsed *rtp)
{
	if (r == w)
		return; // everything left as it was

	if (count == 0) {
		// no extensions, remove header and trim packet
		rtp->rtp_header->v_p_x_cc &= ~0x10;
		size_t pull = rtp->payload - (unsigned char *) rtp->ext_hdr;
		memmove(rtp->ext_hdr, rtp->payload, rtp->payload_len);
		rtp->payload = (unsigned char *) rtp->ext_hdr;
		rtp->ext_hdr = NULL;
		rtp->extension_len = 0;
		skb_trim(skb, skb->len - pull);
		return;
	}

	// shift payload and adjust packet length
	rtp->rtp_header->v_p_x_cc |= 0x90;
	size_t size = w - rtp->extension;
	size_t padded = (size + 3L) & ~3L;
	rtp->ext_hdr->length = htons(padded / 4);

	if (rtp->extension_len >= padded) {
		// shift up payload and trim packet
		memset(w, 0, padded - size);
		size_t pull = rtp->extension_len - padded;
		rtp->extension_len = padded;
		memmove(rtp->payload - pull, rtp->payload, rtp->payload_len);
		rtp->payload -= pull;
		skb_trim(skb, skb->len - pull);
	}
	else {
		// shift down payload and extend packet for padding
		size_t put = padded - size;
		unsigned char *wp = insert_skb_data(&w, skb, rtp, put);
		memset(wp, 0, put);
	}

}

static void apply_extmap_filter_short(struct sk_buff *skb, struct rtpengine_output *o, struct rtp_parsed *rtp) {
	unsigned char *r = rtp->extension; // reader
	unsigned char *end = r + rtp->extension_len;
	unsigned char *w = r; // writer
	unsigned int count = 0; // non-padding extensions

	// XXX partly shared code
	while (r < end) {
		uint8_t id_len = r[0];
		if (id_len == '\0') {
			// padding
			r++; // don't copy padding to *w
			continue;
		}

		uint8_t id = id_len >> 4;
		uint8_t len = (id_len & 0xf) + 1;

		if (!apply_extmap_filter_ext(id, len, 1, &r, &w, end, &count, o))
			break;
	}

	add_extmap_exts_short(&w, &count, o, rtp, skb);

	apply_extmap_filter_finish(r, w, count, o, skb, rtp);
}

static void apply_extmap_filter_long(struct sk_buff *skb, struct rtpengine_output *o, struct rtp_parsed *rtp) {
	unsigned char *r = rtp->extension; // reader
	unsigned char *end = r + rtp->extension_len;
	unsigned char *w = r; // writer
	unsigned int count = 0; // non-padding extensions

	// XXX partly shared code
	while (r < end) {
		uint8_t id = r[0];
		if (id == '\0') {
			// padding
			r++; // don't copy padding to *w
			continue;
		}

		uint8_t len = r[1];

		if (!apply_extmap_filter_ext(id, len, 2, &r, &w, end, &count, o))
			break;
	}

	add_extmap_exts_long(&w, &count, o, rtp, skb);

	apply_extmap_filter_finish(r, w, count, o, skb, rtp);
}

static void add_extmap_hdr_long(struct sk_buff *skb, struct rtpengine_output *o, struct rtp_parsed *rtp) {
	unsigned char *w = rtp->payload; // header goes here
	unsigned int count = 0;

	unsigned char *hdr = insert_skb_data(&w, skb, rtp, 4);
	rtp->ext_hdr = (void *) hdr;

	*hdr++ = 0x10;
	*hdr++ = 0x00;
	hdr += 2; // length

	rtp->extension = (void *) hdr;
	rtp->extension_len = 0;

	unsigned char *r = w;

	add_extmap_exts_long(&w, &count, o, rtp, skb);

	apply_extmap_filter_finish(r, w, count, o, skb, rtp);
}

static void add_extmap_hdr_short(struct sk_buff *skb, struct rtpengine_output *o, struct rtp_parsed *rtp) {
	unsigned char *w = rtp->payload; // header goes here
	unsigned int count = 0;

	unsigned char *hdr = insert_skb_data(&w, skb, rtp, 4);
	rtp->ext_hdr = (void *) hdr;

	*hdr++ = 0xbe;
	*hdr++ = 0xde;
	hdr += 2; // length

	rtp->extension = (void *) hdr;
	rtp->extension_len = 0;

	unsigned char *r = w;

	add_extmap_exts_short(&w, &count, o, rtp, skb);

	apply_extmap_filter_finish(r, w, count, o, skb, rtp);
}

static void apply_extmap_filter(struct sk_buff *skb, struct rtpengine_output *o, struct rtp_parsed *rtp) {
	if (rtp->ext_hdr) {
		if (ntohs(rtp->ext_hdr->undefined) == 0xbede)
			apply_extmap_filter_short(skb, o, rtp);
		else if ((ntohs(rtp->ext_hdr->undefined) & 0xfff0) == 0x0100)
			apply_extmap_filter_long(skb, o, rtp);
		// else: leave untouched
	}
	else {
		// add extension header?
		if (!o->output.extmap_mid)
		{} // nothing
		else if (o->output.extmap_mid > 14)
			add_extmap_hdr_long(skb, o, rtp);
		else
			add_extmap_hdr_short(skb, o, rtp);
	}
	rtp->header_len = rtp->payload - (unsigned char *) rtp->rtp_header;
}


