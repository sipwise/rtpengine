#include "dtmf_rx_fillin.compat"
int main(void) {
	dtmf_rx_state_t *dsp = NULL;
	dtmf_rx_fillin(dsp, 0);
	return 0;
}
