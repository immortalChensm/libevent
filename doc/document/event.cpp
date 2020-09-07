//
// Created by Administrator on 2020/9/7.
//

/**
2020、9、7 本文件用于分析libevent框架的基本工作原理而整理
author:1655664358@qq.com
 **/

//file:util.h
//line:271
#ifdef WIN32
#define evutil_socket_t intptr_t
#else
#define evutil_socket_t int
#endif

#define u64 ev_uint64_t
#define u32 ev_uint32_t
#define u16 ev_uint16_t
#define u8  ev_uint8_t

//event_assign(&base->sig.ev_signal, base, base->sig.ev_signal_pair[1],EV_READ | EV_PERSIST, evsig_cb, base);
//file:event.c
//line:1774
int event_assign(
		struct event *ev,//事件对象
		struct event_base *base,//event_base对象
		evutil_socket_t fd,//文件描述符
		short events,//文件描述上的事件名称【读写】
		void (*callback)(evutil_socket_t, short, void *),//事件回调函数
		void *arg)//回调函数的参数
{
	if (!base)
		base = current_base;
	_event_debug_assert_not_added(ev);

	ev->ev_base = base;
	ev->ev_callback = callback;
	ev->ev_arg = arg;
	ev->ev_fd = fd;
	ev->ev_events = events;
	ev->ev_res = 0;
	ev->ev_flags = EVLIST_INIT;
	ev->ev_ncalls = 0;
	ev->ev_pncalls = NULL;

	if (events & EV_SIGNAL) {

		ev->ev_closure = EV_CLOSURE_SIGNAL;
	} else {
		if (events & EV_PERSIST) {
			evutil_timerclear(&ev->ev_io_timeout);
			ev->ev_closure = EV_CLOSURE_PERSIST;
		} else {
			ev->ev_closure = EV_CLOSURE_NONE;
		}
	}
	min_heap_elem_init(ev);

	if (base != NULL) {

		ev->ev_pri = base->nactivequeues / 2;
	}
	_event_debug_note_setup(ev);

	return 0;
}


//file:event.h
//line:770
#define evsignal_assign(ev, b, x, cb, arg)			\
	event_assign((ev), (b), (x), EV_SIGNAL|EV_PERSIST, cb, (arg))

//file:event-macro.h
//line:105
#define evsignal_assign(ev, b, x, cb, arg)	event_assign((ev), (b), (x), EV_SIGNAL|EV_PERSIST, cb, (arg))

//file:event-internal.h
//line:60
struct eventop {

	const char *name;

	void *(*init)(struct event_base *);

	int (*add)(struct event_base *, evutil_socket_t fd, short old, short events, void *fdinfo);

	int (*del)(struct event_base *, evutil_socket_t fd, short old, short events, void *fdinfo);

	int (*dispatch)(struct event_base *, struct timeval *);

	void (*dealloc)(struct event_base *);

	int need_reinit;

	enum event_method_feature features;

	size_t fdinfo_len;
};
//file:epoll.c
//line:56
struct epollop {
	struct epoll_event *events;
	int nevents;
	int epfd;
};

//file:epoll.c
//line:66
static const struct eventop epollops_changelist = {
		"epoll (with changelist)",
		epoll_init,
		event_changelist_add,
		event_changelist_del,
		epoll_dispatch,
		epoll_dealloc,
		1, /* need reinit */
		EV_FEATURE_ET|EV_FEATURE_O1,
		EVENT_CHANGELIST_FDINFO_SIZE
};

//file:singal.c
//line:93
static const struct eventop evsigops = {
		"signal",
		NULL,
		evsig_add,
		evsig_del,
		NULL,
		NULL,
		0, 0, 0
};

//file:singal.c
//line:168
int evsig_init(struct event_base *base)
{

	//创建全双工的流管道并把创建的管道保存在event_base成员中
	if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, base->sig.ev_signal_pair) == -1)
		return -1;
	}

	//同样设置执行时关闭
	evutil_make_socket_closeonexec(base->sig.ev_signal_pair[0]);
	evutil_make_socket_closeonexec(base->sig.ev_signal_pair[1]);
	base->sig.sh_old = NULL;
	base->sig.sh_old_max = 0;

	//设置为非阻塞IO
	evutil_make_socket_nonblocking(base->sig.ev_signal_pair[0]);
	evutil_make_socket_nonblocking(base->sig.ev_signal_pair[1]);

	event_assign(&base->sig.ev_signal, base, base->sig.ev_signal_pair[1],
				 EV_READ | EV_PERSIST, evsig_cb, base);

	base->sig.ev_signal.ev_flags |= EVLIST_INTERNAL;
	event_priority_set(&base->sig.ev_signal, 0);

	base->evsigsel = &evsigops;

	return 0;
}

//file:epoll.c
//line:107

static void *epoll_init(struct event_base *base)
{
	int epfd;
	struct epollop *epollop;
	if ((epfd = epoll_create(32000)) == -1) {

	}
	//执行就关闭这个文件
	evutil_make_socket_closeonexec(epfd);

	//定义一个epollop结构体变量 然后返回保存在event_base->ev_base=epollop
	if (!(epollop = mm_calloc(1, sizeof(struct epollop)))) {
		close(epfd);
		return (NULL);
	}
	//存放epollfd
	epollop->epfd = epfd;

	//存放epoll_event的值
	/* Initialize fields */
	epollop->events = mm_calloc(INITIAL_NEVENT, sizeof(struct epoll_event));

	epollop->nevents = INITIAL_NEVENT;

	if ((base->flags & EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST) != 0 ||
		((base->flags & EVENT_BASE_FLAG_IGNORE_ENV) == 0 &&
		 evutil_getenv("EVENT_EPOLL_USE_CHANGELIST") != NULL))
		//event_base->evsel保存epoll相关操作的回调函数数组
		base->evsel = &epollops_changelist;

	//信号事件处理器封装初始操作
	//signal.c
	evsig_init(base);

	return (epollop);
}
//file:epoll.c
//line:84
const struct eventop epollops = {
		"epoll",
		epoll_init,
		epoll_nochangelist_add,
		epoll_nochangelist_del,
		epoll_dispatch,
		epoll_dealloc,
		1, /* need reinit */
		EV_FEATURE_ET|EV_FEATURE_O1,
		0
};
//file:select.c
//line:85
const struct eventop selectops = {
		"select",
		select_init,
		select_add,
		select_del,
		select_dispatch,
		select_dealloc,
		0, /* doesn't need reinit. */
		EV_FEATURE_FDS,
		0,
};

//file:event.c
//line:95
static const struct eventop *eventops[] = {
#ifdef _EVENT_HAVE_EVENT_PORTS
		&evportops,
#endif
#ifdef _EVENT_HAVE_WORKING_KQUEUE
		&kqops,
#endif
#ifdef _EVENT_HAVE_EPOLL
		&epollops,
#endif
#ifdef _EVENT_HAVE_DEVPOLL
		&devpollops,
#endif
#ifdef _EVENT_HAVE_POLL
		&pollops,
#endif
#ifdef _EVENT_HAVE_SELECT
		&selectops,
#endif
#ifdef WIN32
		&win32ops,
#endif
		NULL
};

//file:libevent_databash.h
//line:58
enum event_method_feature {
    EV_FEATURE_ET = 0x01,
    EV_FEATURE_O1 = 0x02,
    EV_FEATURE_FDS = 0x04
};
//file:libevent_databash.h
//line:226
enum event_base_config_flag {
	EVENT_BASE_FLAG_NOLOCK = 0x01,
	EVENT_BASE_FLAG_IGNORE_ENV = 0x02,
	EVENT_BASE_FLAG_STARTUP_IOCP = 0x04,
	EVENT_BASE_FLAG_NO_CACHE_TIME = 0x08,
	EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST = 0x10
};

//file:event_macro.h
//line:57
#define	TAILQ_INIT(head) do {						\
	(head)->tqh_first = NULL;					\
	(head)->tqh_last = &(head)->tqh_first;				\
} while (0)


//file:queue.h
//line:277
#define TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}
//file:event_struct.h
//line:68
#ifndef TAILQ_ENTRY
#define _EVENT_DEFINED_TQENTRY
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}
#endif /* !TAILQ_ENTRY */

//file:ht-internal.h
//line:11
#define HT_HEAD(name, type)                                             \
  struct name {                                                         \
                                          \
    struct type **hth_table;                                            \
                              \
    unsigned hth_table_length;                                          \
                    \
    unsigned hth_n_entries;                                             \
    */ \
    unsigned hth_load_limit;                                            \
                 \
    int hth_prime_idx;                                                  \
  }

//file:ht-internal.h
//line:28
#ifdef HT_CACHE_HASH_VALUES
#define HT_ENTRY(type)                          \
  struct {                                      \
    struct type *hte_next;                      \
    unsigned hte_hash;                          \
  }
#else
#define HT_ENTRY(type)                          \
  struct {                                      \
    struct type *hte_next;                      \
  }
#endif


//file:evmap.c
//line:77
struct event_map_entry {
	HT_ENTRY(event_map_entry) map_node;
	//
	struct {
    	struct event_map_entry *hte_next;
  	}map_node;

	evutil_socket_t fd;
	union {

		struct evmap_io evmap_io;
	} ent;
};

#ifdef EVMAP_USE_HT
	#include "ht-internal.h"

	struct event_map_entry;

	HT_HEAD(event_io_map, event_map_entry);
	  struct event_io_map {

    	struct event_map_entry **hth_table;

    	unsigned hth_table_length;

    	unsigned hth_n_entries;

    	unsigned hth_load_limit;

    	int hth_prime_idx;
  	}
#else
	#define event_io_map event_signal_map
#endif


//file:event-internal.h
//line:124
struct event_signal_map {
	/* An array of evmap_io * or of evmap_signal *; empty entries are
	 * set to NULL. */
	//evmap_io I/O事件处理器数组  evmap_signal信号处理器数组
	void **entries;
	/* The number of entries available in entries */
	int nentries;
};


//file:changelist-internal.h
//line:53
struct event_change {

    evutil_socket_t fd;

    short old_events;
    ev_uint8_t read_change;
    ev_uint8_t write_change;
};
//file:event-internal.h
//line:156
struct event_changelist {
    struct event_change *changes;
    int n_changes;
    int changes_size;
};

//file:libevent_database.h
//line:101
struct event {  //事件处理器结构体

    TAILQ_ENTRY(event) ev_active_next;//定义一个匿名结构体变量
    TAILQ_ENTRY(event) ev_next;
    union {
        TAILQ_ENTRY(event) ev_next_with_common_timeout;
        int min_heap_idx;
    } ev_timeout_pos;
    evutil_socket_t ev_fd;//文件描述符、信号值
    struct event_base *ev_base;//所属base
    union {
        struct {
            TAILQ_ENTRY(event) ev_io_next;
            struct timeval ev_timeout;
        } ev_io;

        struct {
            TAILQ_ENTRY(event) ev_signal_next;
            short ev_ncalls;
            short *ev_pncalls;
        } ev_signal;
    } _ev;

    short ev_events;//事件
    short ev_res;
    short ev_flags;//标志位
    ev_uint8_t ev_pri;//优化级
    ev_uint8_t ev_closure;
    struct timeval ev_timeout;
    void (*ev_callback)(evutil_socket_t, short, void *arg);//事件回调函数
    void *ev_arg;//事件回调函数的参数
};

//file:libevent_databash.h
//line:134
struct event_list {
    struct event *tqh_first;
    struct event **tqh_last;
}

//file:evsignal-internal.h
//line:40
struct evsig_info {

    struct event ev_signal;//事件处理器结构体

    evutil_socket_t ev_signal_pair[2];

    int ev_signal_added;

    int ev_n_signals_added;//监听到的信号事件数量


#ifdef _EVENT_HAVE_SIGACTION
    struct sigaction **sh_old;
#else
    ev_sighandler_t **sh_old;//事件处理器函数
#endif

    int sh_old_max;
};
//file:event-internal.h
//line:136
struct common_timeout_list {

    struct event_list events;

    struct timeval duration;

    struct event timeout_event;

    struct event_base *base;
};

//file:defer-internal.h
//line:38
typedef void (*deferred_cb_fn)(struct deferred_cb *, void *);

//file:defer-internal.h
//line:42
struct deferred_cb {

    TAILQ_ENTRY (deferred_cb) cb_next;
    struct {								\
	    struct deferred_cb *tqe_next;	/* next element */			\
	    struct deferred_cb **tqe_prev;	/* address of previous next element */	\
    }cb_next;

    unsigned queued : 1;
    deferred_cb_fn cb;

    void *arg;
};

//file:defer-internal.h
//line:54
struct deferred_cb_queue {
    void *lock;

    int active_count;

    void (*notify_fn)(struct deferred_cb_queue *, void *);
    void *notify_arg;


    TAILQ_HEAD (deferred_cb_list, deferred_cb) deferred_cb_list;
    //在此定义的结构体变量
    struct deferred_cb_list {								\
	    struct deferred_cb *tqh_first;	/* first element */			\
	    struct deferred_cb **tqh_last;	/* addr of last next element */		\
    }deferred_cb_list;
};
//file:minheap-internal.h
//line:38
typedef struct min_heap
{
	struct event** p;
	unsigned n, a;
} min_heap_t;

//file:event-internal.h
//line:170
struct event_base {

    const struct eventop *evsel;

    void *evbase;

    struct event_changelist changelist;

    const struct eventop *evsigsel;

    struct evsig_info sig;

    int virtual_event_count;

    int event_count;

    int event_count_active;

    int event_gotterm;

    int event_break;

    int event_continue;

    int event_running_priority;

    int running_loop;

    struct event_list *activequeues;

    int nactivequeues;

    struct common_timeout_list **common_timeout_queues;

    int n_common_timeouts;

    int n_common_timeouts_allocated;

    struct deferred_cb_queue defer_queue;

    struct event_io_map io;//io事件处理器池

    struct event_signal_map sigmap;//信号事件处理器池

    struct event_list eventqueue;

    struct timeval event_tv;

    struct min_heap timeheap;

    struct timeval tv_cache;

#if defined(_EVENT_HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)

	struct timeval tv_clock_diff;

	time_t last_updated_clock_diff;
#endif

#ifndef _EVENT_DISABLE_THREAD_SUPPORT

    unsigned long th_owner_id;

    void *th_base_lock;

    struct event *current_event;

    void *current_event_cond;

    int current_event_waiters;
#endif

#ifdef WIN32

	struct event_iocp_port *iocp;
#endif

    enum event_base_config_flag flags;

    int is_notify_pending;

    evutil_socket_t th_notify_fd[2];

    struct event th_notify;

    int (*th_notify_fn)(struct event_base *base);
};

void event_deferred_cb_queue_init(struct deferred_cb_queue *cb)
{
	memset(cb, 0, sizeof(struct deferred_cb_queue));
	TAILQ_INIT(&cb->deferred_cb_list);
}

//line:event.c
//line:2066
static int  evthread_notify_base(struct event_base *base)
{
	EVENT_BASE_ASSERT_LOCKED(base);
	if (!base->th_notify_fn)
		return -1;
	if (base->is_notify_pending)
		return 0;
	base->is_notify_pending = 1;
	return base->th_notify_fn(base);
}


//line:event.c
//line:508
static void  notify_base_cbq_callback(struct deferred_cb_queue *cb, void *baseptr)
{
	struct event_base *base = baseptr;
	if (EVBASE_NEED_NOTIFY(base))
		evthread_notify_base(base);
}
//line:evmap.c
//line:506
void event_changelist_init(struct event_changelist *changelist)
{
	changelist->changes = NULL;
	changelist->changes_size = 0;
	changelist->n_changes = 0;
}

//line:evmap.c
//line:225
void evmap_signal_initmap(struct event_signal_map *ctx)
{
	ctx->nentries = 0;
	ctx->entries = NULL;
}

//line:evmap.c
//line:185
void evmap_io_initmap(struct event_io_map* ctx)
{
	evmap_signal_initmap(ctx);
}
//line:event-internal.c
//line:309
struct event_config_entry {
	TAILQ_ENTRY(event_config_entry) next;

	struct {
		struct event_config_entry *tqe_next;	/* next element */
		struct event_config_entry **tqe_prev;	/* address of previous next element */
	}next;


	const char *avoid_method;
};

//line:event-internal.c
//line:341
struct event_config {

	TAILQ_HEAD(event_configq, event_config_entry) entries;
	struct event_configq {
		struct event_config_entry *tqh_first;
		struct event_config_entry **tqh_last;
	}entries;


	int n_cpus_hint;
	//枚举变量  功能特征
	//位于event.h头文件中
	enum event_method_feature require_features;
	enum event_base_config_flag flags;
};

//line:event.c
//line:464
static int event_config_is_avoided_method(const struct event_config *cfg, const char *method)
{
	struct event_config_entry *entry;

	TAILQ_FOREACH(entry, &cfg->entries, next) {
		if (entry->avoid_method != NULL &&
			strcmp(entry->avoid_method, method) == 0)
			return (1);
	}

	return (0);
}
//line:event.c
//line:2011
int event_add(struct event *ev, const struct timeval *tv)
{
	int res;

	res = event_add_internal(ev, tv, 0);

	return (res);
}
//line:evmap.c
//line:262
int evmap_io_add(struct event_base *base, evutil_socket_t fd, struct event *ev)
{
	const struct eventop *evsel = base->evsel;
	struct event_io_map *io = &base->io;
	struct evmap_io *ctx = NULL;
	int nread, nwrite, retval = 0;
	short res = 0, old = 0;
	struct event *old_ev;

	EVUTIL_ASSERT(fd == ev->ev_fd);

	if (fd < 0)
		return 0;

#ifndef EVMAP_USE_HT
	if (fd >= io->nentries) {
		if (evmap_make_space(io, fd, sizeof(struct evmap_io *)) == -1)
			return (-1);
	}
#endif
	GET_IO_SLOT_AND_CTOR(ctx, io, fd, evmap_io, evmap_io_init,
						 evsel->fdinfo_len);

	nread = ctx->nread;
	nwrite = ctx->nwrite;

	if (nread)
		old |= EV_READ;
	if (nwrite)
		old |= EV_WRITE;

	if (ev->ev_events & EV_READ) {
		if (++nread == 1)
			res |= EV_READ;
	}
	if (ev->ev_events & EV_WRITE) {
		if (++nwrite == 1)
			res |= EV_WRITE;
	}
	if (EVUTIL_UNLIKELY(nread > 0xffff || nwrite > 0xffff)) {
		event_warnx("Too many events reading or writing on fd %d",
					(int)fd);
		return -1;
	}
	if (EVENT_DEBUG_MODE_IS_ON() &&
		(old_ev = TAILQ_FIRST(&ctx->events)) &&
		(old_ev->ev_events&EV_ET) != (ev->ev_events&EV_ET)) {
		event_warnx("Tried to mix edge-triggered and non-edge-triggered"
					" events on fd %d", (int)fd);
		return -1;
	}

	if (res) {
		void *extra = ((char*)ctx) + sizeof(struct evmap_io);
		/* XXX(niels): we cannot mix edge-triggered and
		 * level-triggered, we should probably assert on
		 * this. */
		if (evsel->add(base, ev->ev_fd,
					   old, (ev->ev_events & EV_ET) | res, extra) == -1)
			return (-1);
		retval = 1;
	}

	ctx->nread = (ev_uint16_t) nread;
	ctx->nwrite = (ev_uint16_t) nwrite;
	TAILQ_INSERT_TAIL(&ctx->events, ev, ev_io_next);

	return (retval);
}
//line:event.c
//line:2082
//*ev 事件处理器
static inline int event_add_internal(struct event *ev, const struct timeval *tv,
				   int tv_is_absolute)
{
	struct event_base *base = ev->ev_base;
	int res = 0;
	int notify = 0;

	if (tv != NULL && !(ev->ev_flags & EVLIST_TIMEOUT)) {
		if (min_heap_reserve(&base->timeheap,
							 1 + min_heap_size(&base->timeheap)) == -1)
			return (-1);  /* ENOMEM == errno */
	}

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
	if (base->current_event == ev && (ev->ev_events & EV_SIGNAL)
		&& !EVBASE_IN_THREAD(base)) {
		++base->current_event_waiters;
		EVTHREAD_COND_WAIT(base->current_event_cond, base->th_base_lock);
	}
#endif

	if ((ev->ev_events & (EV_READ|EV_WRITE|EV_SIGNAL)) &&
		!(ev->ev_flags & (EVLIST_INSERTED|EVLIST_ACTIVE))) {
		if (ev->ev_events & (EV_READ|EV_WRITE))
			res = evmap_io_add(base, ev->ev_fd, ev);
		else if (ev->ev_events & EV_SIGNAL)
			res = evmap_signal_add(base, (int)ev->ev_fd, ev);
		if (res != -1)
			//记录哪些事件处理器已经插入了
			event_queue_insert(base, ev, EVLIST_INSERTED);
		if (res == 1) {
			/* evmap says we need to notify the main thread. */
			notify = 1;
			res = 0;
		}
	}

	//定时事件处理器的插入

	if (res != -1 && tv != NULL) {
		struct timeval now;
		int common_timeout;

		if (ev->ev_closure == EV_CLOSURE_PERSIST && !tv_is_absolute)
			ev->ev_io_timeout = *tv;

		if (ev->ev_flags & EVLIST_TIMEOUT) {
			/* XXX I believe this is needless. */
			if (min_heap_elt_is_top(ev))
				notify = 1;
			event_queue_remove(base, ev, EVLIST_TIMEOUT);
		}
		if ((ev->ev_flags & EVLIST_ACTIVE) &&
			(ev->ev_res & EV_TIMEOUT)) {
			if (ev->ev_events & EV_SIGNAL) {

				if (ev->ev_ncalls && ev->ev_pncalls) {
					/* Abort loop */
					*ev->ev_pncalls = 0;
				}
			}

			event_queue_remove(base, ev, EVLIST_ACTIVE);
		}

		gettime(base, &now);

		common_timeout = is_common_timeout(tv, base);
		if (tv_is_absolute) {
			ev->ev_timeout = *tv;
		} else if (common_timeout) {
			struct timeval tmp = *tv;
			tmp.tv_usec &= MICROSECONDS_MASK;
			evutil_timeradd(&now, &tmp, &ev->ev_timeout);
			ev->ev_timeout.tv_usec |=
					(tv->tv_usec & ~MICROSECONDS_MASK);
		} else {
			evutil_timeradd(&now, tv, &ev->ev_timeout);
		}

		event_debug((
							"event_add: timeout in %d seconds, call %p",
									(int)tv->tv_sec, ev->ev_callback));

		event_queue_insert(base, ev, EVLIST_TIMEOUT);
		if (common_timeout) {
			struct common_timeout_list *ctl =
					get_common_timeout_list(base, &ev->ev_timeout);
			if (ev == TAILQ_FIRST(&ctl->events)) {
				common_timeout_schedule(ctl, &now, ev);
			}
		} else {

			if (min_heap_elt_is_top(ev))
				notify = 1;
		}
	}

	if (res != -1 && notify && EVBASE_NEED_NOTIFY(base))
		evthread_notify_base(base);

	_event_debug_note_add(ev);

	return (res);
}
//line:event.c
//line:554
struct event_base *event_base_new_with_config(const struct event_config *cfg)
{
	struct event_base *base;
	if ((base = mm_calloc(1, sizeof(struct event_base))) == NULL) {
		event_warn("%s: calloc", __func__);
		return NULL;
	}
	gettime(base, &base->event_tv);
	//file:minheap-internal.h
	//line:44
	min_heap_ctor(&base->timeheap);
	TAILQ_INIT(&base->eventqueue);
	(base->eventqueue)->tqh_first = NULL;
	(base->eventqueue)->tqh_last = &(head)->tqh_first;

	base->sig.ev_signal_pair[0] = -1;
	base->sig.ev_signal_pair[1] = -1;

	base->th_notify_fd[0] = -1;
	base->th_notify_fd[1] = -1;


	event_deferred_cb_queue_init(&base->defer_queue);

	base->defer_queue.notify_fn = notify_base_cbq_callback;
	base->defer_queue.notify_arg = base;

	if (cfg)
		base->flags = cfg->flags;
	evmap_io_initmap(&base->io);

	evmap_signal_initmap(&base->sigmap);
	event_changelist_init(&base->changelist);
	base->evbase = NULL;

	for (i = 0; eventops[i] && !base->evbase; i++) {
		if (cfg != NULL) {

			//可以选择select/epoll[其它不管了]
			if (event_config_is_avoided_method(cfg,
											   eventops[i]->name))
				continue;
			if ((eventops[i]->features & cfg->require_features)
				!= cfg->require_features)
				continue;
		}

		if (should_check_environment &&
			event_is_method_disabled(eventops[i]->name))
			continue;
		base->evsel = eventops[i];//select 或是epoll[selectops,epollops]

		//select/epoll 的init 初始化函数【具体看select.c,epoll.c文件]】
		base->evbase = base->evsel->init(base);
		//会随便给成员
		//const struct eventop *evsigsel; 设置信号处理函数

		//struct evsig_info sig;给sig成员设置对应的信号事件处理器[事件处理器有文件描述符/信号值，处理函数，参数等]
	}

	//line:2820
	//给 struct event th_notify; 设置通知事件处理器
	//给 th_notify_fn=evthread_notify_base_default(struct event_base *base)
	r = evthread_make_base_notifiable(base);

}