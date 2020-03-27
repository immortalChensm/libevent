//
// Created by 1655664358@qq.com on 2020/3/26.
//

#ifndef _LIBEVENT_DATABASE_H_
#define _LIBEVENT_DATABASE_H_


/******************define 区******************/
#define evutil_socket_t int
#define EV_TIMEOUT	0x01
#define EV_READ		0x02
#define EV_WRITE	0x04
#define EV_SIGNAL	0x08
#define EV_PERSIST	0x10
#define EV_ET       0x20
#define EV_CLOSURE_NONE 0
#define EV_CLOSURE_SIGNAL 1
#define EV_CLOSURE_PERSIST 2
#define INITIAL_NEVENT 32
#define event_io_map event_signal_map
#define mm_malloc(sz) event_mm_malloc_(sz)
#define EVLIST_TIMEOUT	0x01
#define EVLIST_INSERTED	0x02
#define EVLIST_SIGNAL	0x04
#define EVLIST_ACTIVE	0x08
#define EVLIST_INTERNAL	0x10
#define EVLIST_INIT	0x80

#define EVLIST_ALL	(0xf000 | 0x9f)


#define mm_calloc(count, size) event_mm_calloc_((count), (size))

GLOBAL int _evthread_lock_debugging_enabled = 0;
int _evthread_is_debug_lock_held(void *lock);

#define EVUTIL_UNLIKELY(p) (p)

#define EVUTIL_ASSERT(cond)						\
		if (EVUTIL_UNLIKELY(!(cond))) {				\
			abort();					\
		}							\

#define EVLOCK_ASSERT_LOCKED(lock)					\
		if ((lock) && _evthread_lock_debugging_enabled) {	\
			EVUTIL_ASSERT(_evthread_is_debug_lock_held(lock)); \
		}							\


#define EVENT_BASE_ASSERT_LOCKED(base)		\
	EVLOCK_ASSERT_LOCKED((base)->th_base_lock)

#define HT_INIT(name, head)          name##_HT_INIT(head)
#define HT_ENTRY(type)                          \
  struct {                                      \
    struct type *hte_next;                      \
  }
#define	TAILQ_INIT(head) do {						\
	(head)->tqh_first = NULL;					\
	(head)->tqh_last = &(head)->tqh_first;				\
} while (0)

#define TAILQ_HEAD(name, type)						\
struct event_configq {								\
	struct event_config_entry *tqh_first;	/* first element */			\
	struct event_config_entry **tqh_last;	/* addr of last next element */		\
}


int evsig_init(struct event_base *base);
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}#define TAILQ_HEAD(name, type)						\

struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}
struct event_debug_entry {
	HT_ENTRY(event_debug_entry) node;
	const struct event *ptr;
	unsigned added : 1;
};

extern int _event_debug_mode_on;

static int evsig_add(struct event_base *, evutil_socket_t, short, short, void *);
static int evsig_del(struct event_base *, evutil_socket_t, short, short, void *);
static const struct eventop evsigops = {
        "signal",
        NULL,
        evsig_add,
        evsig_del,
        NULL,
        NULL,
        0, 0, 0
};

#define EVBASE_NEED_NOTIFY(base)			 \
	(_evthread_id_fn != NULL &&			 \
	    (base)->running_loop &&			 \
	    (base)->th_owner_id != _evthread_id_fn())

#define _event_debug_assert_not_added(ev) do {				\
	if (_event_debug_mode_on) {					\
		struct event_debug_entry *dent,find;			\
		find.ptr = (ev);					\
		EVLOCK_LOCK(_event_debug_map_lock, 0);			\
		dent = HT_FIND(event_debug_map, &global_debug_map, &find); \
		if (dent && dent->added) {				\

		}							\
		EVLOCK_UNLOCK(_event_debug_map_lock, 0);		\
	}								\
	} while (0)

#define EVTHREAD_LOCKING_ENABLED()		\
	(_evthread_lock_fns.lock != NULL)
#define N_ACTIVE_CALLBACKS(base)					\
	((base)->event_count_active + (base)->defer_queue.active_count)
#ifdef _EVENT_HAVE_TIMERCLEAR
#define evutil_timerclear(tvp) timerclear(tvp)
#else
#define	evutil_timerclear(tvp)	(tvp)->tv_sec = (tvp)->tv_usec = 0
#endif

#define	evutil_timercmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	 ((tvp)->tv_usec cmp (uvp)->tv_usec) :				\
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))

	 //信号事件
#define evsignal_add(ev, tv)		event_add((ev), (tv))

#define evsignal_assign(ev, b, x, cb, arg)	event_assign((ev), (b), (x), EV_SIGNAL|EV_PERSIST, cb, (arg))
//信号事件处理器创建接口
#define evsignal_new(b, x, cb, arg) event_new((b), (x), EV_SIGNAL|EV_PERSIST, (cb), (arg))

#define evsignal_del(ev)		event_del(ev)

#define evsignal_pending(ev, tv)	event_pending((ev), EV_SIGNAL, (tv))

#define evsignal_initialized(ev)	event_initialized(ev)

//定时事件
#define evtimer_assign(ev, b, cb, arg) event_assign((ev), (b), -1, 0, (cb), (arg))
//定时事件处理器接口
#define evtimer_new(b, cb, arg)	       event_new((b), -1, 0, (cb), (arg))

#define evtimer_add(ev, tv)		event_add((ev), (tv))

#define evtimer_del(ev)			event_del(ev)

#define evtimer_pending(ev, tv)		event_pending((ev), EV_TIMEOUT, (tv))

#define evtimer_initialized(ev)		event_initialized(ev)

#define GET_SIGNAL_SLOT_AND_CTOR(x, map, slot, type, ctor, fdinfo_len)	\
	do {
	//map 信号事件数组
		if ((map)->entries[slot] == NULL) {			\
		//
			(map)->entries[slot] =				\
			    mm_calloc(1,sizeof(struct type)+fdinfo_len); \
			if (EVUTIL_UNLIKELY((map)->entries[slot] == NULL)) \
				return (-1);				\
			(ctor)((struct type *)(map)->entries[slot]);	\
		}							\
		(x) = (struct type *)((map)->entries[slot]);
	} while (0)

#define GET_IO_SLOT_AND_CTOR(x,map,slot,type,ctor,fdinfo_len) GET_SIGNAL_SLOT_AND_CTOR(x,map,slot,type,ctor,fdinfo_len)

#define TAILQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.tqe_next = NULL;					\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &(elm)->field.tqe_next;			\
} while (0)

/******************define 区******************/
extern unsigned long (*_evthread_id_fn)(void);
GLOBAL unsigned long (*_evthread_id_fn)(void) = NULL;
static inline void	     min_heap_ctor(min_heap_t* s);
static void *(*_mm_malloc_fn)(size_t sz) = NULL;
static void *(*_mm_realloc_fn)(void *p, size_t sz) = NULL;
static void (*_mm_free_fn)(void *p) = NULL;
struct event_signal_map {
	void **entries;
	int nentries;
};

enum event_method_feature {
            EV_FEATURE_ET = 0x01,
            EV_FEATURE_O1 = 0x02,
            EV_FEATURE_FDS = 0x04
};
struct evthread_lock_callbacks {

    int lock_api_version;
    unsigned supported_locktypes;
    void *(*alloc)(unsigned locktype);
    void (*free)(void *lock, unsigned locktype);
    int (*lock)(unsigned mode, void *lock);
    int (*unlock)(unsigned mode, void *lock);
};

struct evthread_condition_callbacks {

    int condition_api_version;

    void *(*alloc_condition)(unsigned condtype);

    void (*free_condition)(void *cond);

    int (*signal_condition)(void *cond, int broadcast);
    int (*wait_condition)(void *cond, void *lock,const struct timeval *timeout);
};

struct evthread_lock_callbacks _evthread_lock_fns;
struct evthread_condition_callbacks _evthread_cond_fns;

struct debug_lock {
	unsigned locktype;
	unsigned long held_by;
	int count;
	void *lock;
};

typedef struct min_heap
{
    struct event** p;
    unsigned n, a;
} min_heap_t;

struct event {  //事件处理器结构体

    TAILQ_ENTRY(event) ev_active_next;//定义一个匿名结构体变量
    TAILQ_ENTRY(event) ev_next;
    union {
        TAILQ_ENTRY(event) ev_next_with_common_timeout;
        int min_heap_idx;
    } ev_timeout_pos;
    evutil_socket_t ev_fd;
    struct event_base *ev_base;
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

    short ev_events;
    short ev_res;
    short ev_flags;
    ev_uint8_t ev_pri;
    ev_uint8_t ev_closure;
    struct timeval ev_timeout;
    void (*ev_callback)(evutil_socket_t, short, void *arg);//事件回调函数
    void *ev_arg;//事件回调函数的参数
};

struct event_list {
	struct event *tqh_first;
	struct event **tqh_last;
}
struct evmap_signal {
	struct event_list events;
};

struct evmap_io {
	struct event_list events;
	ev_uint16_t nread;
	ev_uint16_t nwrite;
};
struct event_signal_map {
	void **entries;
	int nentries;
};
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
struct epollop {
	struct epoll_event *events;
	int nevents;
	int epfd;
};

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

enum event_base_config_flag {
			EVENT_BASE_FLAG_NOLOCK = 0x01,
			EVENT_BASE_FLAG_IGNORE_ENV = 0x02,
			EVENT_BASE_FLAG_STARTUP_IOCP = 0x04,
			EVENT_BASE_FLAG_NO_CACHE_TIME = 0x08,
			EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST = 0x10
};

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

struct event_changelist {
    struct event_change *changes;
    int n_changes;
    int changes_size;
};
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
struct common_timeout_list {
    struct event_list events;
    struct timeval duration;
    struct event timeout_event;
    struct event_base *base;
};
typedef void (*deferred_cb_fn)(struct deferred_cb *, void *);
struct deferred_cb {
    TAILQ_ENTRY (deferred_cb) cb_next;
    unsigned queued : 1;
    deferred_cb_fn cb;
    void *arg;
};

struct deferred_cb_list {								\
	struct deferred_cb *tqh_first;	/* first element */			\
	struct deferred_cb **tqh_last;	/* addr of last next element */		\
}

struct deferred_cb_queue {

    void *lock;
    int active_count;
    void (*notify_fn)(struct deferred_cb_queue *, void *);
    void *notify_arg;
    TAILQ_HEAD (deferred_cb_list, deferred_cb) deferred_cb_list;
};

struct event_config {

	TAILQ_HEAD(event_configq, event_config_entry) entries;

	int n_cpus_hint;

	enum event_method_feature require_features;
	enum event_base_config_flag flags;
};

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
    struct event_io_map io;//io事件处理器数组  与信号数据结构一致  数据结构放于有道笔记
    struct event_signal_map sigmap;//存放信号事件处理器数组
    struct event_list eventqueue;
    struct timeval event_tv;
    struct min_heap timeheap;//定时TIMEOUT事件处理器数组
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

#endif