#include "fix_frame_channel_layout.compat"
int main(void) {
	AVFrame *f = NULL;
	fix_frame_channel_layout(f);
	return 0;
}
