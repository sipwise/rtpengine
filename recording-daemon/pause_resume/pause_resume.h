#ifndef RECORDING_DAEMON_PAUSE_RESUME_PAUSE_RESUME_H_
#define RECORDING_DAEMON_PAUSE_RESUME_PAUSE_RESUME_H_

void pause_ctrl_stop_recording(char *call_id);
void pause_ctrl_start_recording(char *call_id);
void pause_ctrl_destroy(pause_ctrl_t *pr_ctrl);

#endif /* RECORDING_DAEMON_PAUSE_RESUME_PAUSE_RESUME_H_ */
