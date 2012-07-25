#ifndef __POLLER_H__
#define __POLLER_H__



#include <sys/types.h>
#include <time.h>
#include <glib.h>



struct poller_item {
	int				fd;
	void				*ptr;

	void				(*readable)(int, void *);
	void				(*writeable)(int, void *);
	void				(*closed)(int, void *);
	void				(*timer)(int, void *);

	int				blocked:1;
	int				error:1;
};

struct poller {
	int				fd;
	struct poller_item		**items;
	unsigned int			items_size;
	GList				*timers;

	time_t				now;
};


struct poller *poller_new(void);
int poller_add_item(struct poller *, struct poller_item *);
int poller_update_item(struct poller *, struct poller_item *);
int poller_del_item(struct poller *, int);
int poller_poll(struct poller *, int);
void poller_blocked(struct poller *, int);
int poller_isblocked(struct poller *, int);
void poller_error(struct poller *, int);

int poller_timer(struct poller *, void (*)(void *), void *);


#endif
