#define SPAN_LOG_ARGS int level, const char *text
#define PHASE_E_HANDLER_ARGS t30_state_t *s, void *user_data, int result
INLINE void my_span_set_log(logging_state_t *ls, message_handler_func_t h) {
	span_log_set_message_handler(ls, h);
}
INLINE void my_span_mh(message_handler_func_t h) {
	span_set_message_handler(h);
}
