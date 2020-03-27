//
// Created by 1655664358@qq.com on 2020/3/26.
//
#include "libevent_database.h"
#include "epoll.c"

void min_heap_ctor(min_heap_t* s) {
    s->p = 0; s->n = 0; s->a = 0;
}
static int evthread_notify_base(struct event_base *base)
{
    EVENT_BASE_ASSERT_LOCKED(base);
    if (!base->th_notify_fn)
        return -1;
    if (base->is_notify_pending)
        return 0;
    base->is_notify_pending = 1;
    return base->th_notify_fn(base);
}

int _evthread_is_debug_lock_held(void *lock_)
{
    struct debug_lock *lock = lock_;
    if (! lock->count)
        return 0;
    if (_evthread_id_fn) {
        unsigned long me = _evthread_id_fn();
        if (lock->held_by != me)
            return 0;
    }
    return 1;
}

static void evsig_cb(evutil_socket_t fd, short what, void *arg)
{
    static char signals[1024];
    ev_ssize_t n;
    int i;
    int ncaught[NSIG];
    struct event_base *base;

    base = arg;

    memset(&ncaught, 0, sizeof(ncaught));

    while (1) {
        n = recv(fd, signals, sizeof(signals), 0);
        if (n == -1) {
            int err = evutil_socket_geterror(fd);
            if (! EVUTIL_ERR_RW_RETRIABLE(err))
                event_sock_err(1, fd, "%s: recv", __func__);
            break;
        } else if (n == 0) {
            /* XXX warn? */
            break;
        }
        for (i = 0; i < n; ++i) {
            ev_uint8_t sig = signals[i];
            if (sig < NSIG)
                ncaught[sig]++;
        }
    }

    EVBASE_ACQUIRE_LOCK(base, th_base_lock);
    for (i = 0; i < NSIG; ++i) {
        if (ncaught[i])
            evmap_signal_active(base, i, ncaught[i]);
    }
    EVBASE_RELEASE_LOCK(base, th_base_lock);
}

void *event_mm_calloc_(size_t count, size_t size)
{
    if (_mm_malloc_fn) {
        size_t sz = count * size;
        void *p = _mm_malloc_fn(sz);
        if (p)
            memset(p, 0, sz);
        return p;
    } else
        return calloc(count, size);
}

static void detect_monotonic(void)
{
#if defined(_EVENT_HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    struct timespec	ts;
	static int use_monotonic_initialized = 0;

	if (use_monotonic_initialized)
		return;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
		use_monotonic = 1;

	use_monotonic_initialized = 1;
#endif
}

static int gettime(struct event_base *base, struct timeval *tp)
{

    EVENT_BASE_ASSERT_LOCKED(base);
    if (base->tv_cache.tv_sec) {
        *tp = base->tv_cache;
        return (0);
    }

#if defined(_EVENT_HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
	if (use_monotonic) {
		struct timespec	ts;
		if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
			return (-1);

		tp->tv_sec = ts.tv_sec;
		tp->tv_usec = ts.tv_nsec / 1000;
		if (base->last_updated_clock_diff + CLOCK_SYNC_INTERVAL
		    < ts.tv_sec) {
			struct timeval tv;
			evutil_gettimeofday(&tv,NULL);
			evutil_timersub(&tv, tp, &base->tv_clock_diff);
			base->last_updated_clock_diff = ts.tv_sec;
		}

		return (0);
	}
#endif

    return (evutil_gettimeofday(tp, NULL));
}

static void notify_base_cbq_callback(struct deferred_cb_queue *cb, void *baseptr)
{
    struct event_base *base = baseptr;
    if (EVBASE_NEED_NOTIFY(base))
        evthread_notify_base(base);
}

void event_deferred_cb_queue_init(struct deferred_cb_queue *cb)
{
    memset(cb, 0, sizeof(struct deferred_cb_queue));
    TAILQ_INIT(&cb->deferred_cb_list);
}

int evutil_make_socket_closeonexec(evutil_socket_t fd)
{
#if !defined(WIN32) && defined(_EVENT_HAVE_SETFD)
    int flags;
	if ((flags = fcntl(fd, F_GETFD, NULL)) < 0) {
		event_warn("fcntl(%d, F_GETFD)", fd);
		return -1;
	}
	//一执行此文件就会关闭
	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
		event_warn("fcntl(%d, F_SETFD)", fd);
		return -1;
	}
#endif
    return 0;
}
static int evutil_issetugid(void)
{
#ifdef _EVENT_HAVE_ISSETUGID
    return issetugid();
#else

#ifdef _EVENT_HAVE_GETEUID
    if (getuid() != geteuid())
		return 1;
#endif
#ifdef _EVENT_HAVE_GETEGID
    if (getgid() != getegid())
		return 1;
#endif
    return 0;
#endif
}

const char *evutil_getenv(const char *varname)
{
    if (evutil_issetugid())
        return NULL;

    return getenv(varname);
}
int evutil_socketpair(int family, int type, int protocol, evutil_socket_t fd[2])
{
#ifndef WIN32
    return socketpair(family, type, protocol, fd);
#else
    return evutil_ersatz_socketpair(family, type, protocol, fd);
#endif
}

int evutil_make_socket_nonblocking(evutil_socket_t fd)
{
#ifdef WIN32
    {
        u_long nonblocking = 1;
        if (ioctlsocket(fd, FIONBIO, &nonblocking) == SOCKET_ERROR) {
            event_sock_warn(fd, "fcntl(%d, F_GETFL)", (int)fd);
            return -1;
        }
    }
#else
    {
		int flags;
		if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
			event_warn("fcntl(%d, F_GETFL)", fd);
			return -1;
		}
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			event_warn("fcntl(%d, F_SETFL)", fd);
			return -1;
		}
	}
#endif
    return 0;
}

void min_heap_elem_init(struct event* e) {
    e->ev_timeout_pos.min_heap_idx = -1;
}
int event_assign(struct event *ev, struct event_base *base, evutil_socket_t fd, short events, void (*callback)(evutil_socket_t, short, void *), void *arg)
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
        if ((events & (EV_READ|EV_WRITE)) != 0) {
            event_warnx("%s: EV_SIGNAL is not compatible with "
                        "EV_READ or EV_WRITE", __func__);
            return -1;
        }
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
        /* by default, we put new events into the middle priority */
        ev->ev_pri = base->nactivequeues / 2;
    }

    _event_debug_note_setup(ev);

    return 0;
}

static int evsig_add(struct event_base *base, evutil_socket_t evsignal, short old, short events, void *p)
{
    struct evsig_info *sig = &base->sig;
    (void)p;

    EVUTIL_ASSERT(evsignal >= 0 && evsignal < NSIG);

    /* catch signals if they happen quickly */
    EVSIGBASE_LOCK();
    if (evsig_base != base && evsig_base_n_signals_added) {
    }
    evsig_base = base;
    evsig_base_n_signals_added = ++sig->ev_n_signals_added;
    evsig_base_fd = base->sig.ev_signal_pair[0];
    EVSIGBASE_UNLOCK();

    event_debug(("%s: %d: changing signal handler", __func__, (int)evsignal));
    if (_evsig_set_handler(base, (int)evsignal, evsig_handler) == -1) {
        goto err;
    }


    if (!sig->ev_signal_added) {
        if (event_add(&sig->ev_signal, NULL))
            goto err;
        sig->ev_signal_added = 1;
    }

    return (0);

    err:
    EVSIGBASE_LOCK();
    --evsig_base_n_signals_added;
    --sig->ev_n_signals_added;
    EVSIGBASE_UNLOCK();
    return (-1);
}

static int evsig_del(struct event_base *base, evutil_socket_t evsignal, short old, short events, void *p)
{
    EVUTIL_ASSERT(evsignal >= 0 && evsignal < NSIG);

    event_debug(("%s: "EV_SOCK_FMT": restoring signal handler",
            __func__, EV_SOCK_ARG(evsignal)));

    EVSIGBASE_LOCK();
    --evsig_base_n_signals_added;
    --base->sig.ev_n_signals_added;
    EVSIGBASE_UNLOCK();

    return (_evsig_restore_handler(base, (int)evsignal));
}

int event_priority_set(struct event *ev, int pri)
{
    _event_debug_assert_is_setup(ev);

    if (ev->ev_flags & EVLIST_ACTIVE)
        return (-1);
    if (pri < 0 || pri >= ev->ev_base->nactivequeues)
        return (-1);

    ev->ev_pri = pri;

    return (0);
}

int evsig_init(struct event_base *base)
{

    //创建双向流管道
    if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, base->sig.ev_signal_pair) == -1) {
        return -1;
    }
    //对管道进行设置
    evutil_make_socket_closeonexec(base->sig.ev_signal_pair[0]);
    evutil_make_socket_closeonexec(base->sig.ev_signal_pair[1]);
    base->sig.sh_old = NULL;
    base->sig.sh_old_max = 0;

    //设置为非阻塞IO
    evutil_make_socket_nonblocking(base->sig.ev_signal_pair[0]);
    evutil_make_socket_nonblocking(base->sig.ev_signal_pair[1]);
    //sig.ev_signal 信号事件处理器
    //socketpai[1]写管道文件
    //读事件|持续永久
    //evsig_cb 信号事件回调函数
    //把事件，双向流管道文件，回调函数，回调函数的参数等封装并保存在event_base.sig.ev_signal中
    event_assign(&base->sig.ev_signal, base, base->sig.ev_signal_pair[1],EV_READ | EV_PERSIST, evsig_cb, base);

    base->sig.ev_signal.ev_flags |= EVLIST_INTERNAL;
    event_priority_set(&base->sig.ev_signal, 0);

    base->evsigsel = &evsigops;

    return 0;
}


static void *epoll_init(struct event_base *base)
{
    int epfd;
    struct epollop *epollop;

    if ((epfd = epoll_create(32000)) == -1) {
        if (errno != ENOSYS)
            event_warn("epoll_create");
        return (NULL);
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
    if (epollop->events == NULL) {
        mm_free(epollop);
        close(epfd);
        return (NULL);
    }
    epollop->nevents = INITIAL_NEVENT;

    if ((base->flags & EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST) != 0 ||
        ((base->flags & EVENT_BASE_FLAG_IGNORE_ENV) == 0 &&
         evutil_getenv("EVENT_EPOLL_USE_CHANGELIST") != NULL))
        //event_base->evsel保存epoll相关操作的回调函数数组
        base->evsel = &epollops_changelist;

    //信号事件处理器封装初始操作
    evsig_init(base);

    return (epollop);
}

void evmap_io_initmap(struct event_io_map *ctx)
{
    HT_INIT(event_io_map, ctx);
}

void evmap_signal_initmap(struct event_signal_map *ctx)
{
    ctx->nentries = 0;
    ctx->entries = NULL;
}

void evmap_signal_initmap(struct event_signal_map *ctx)
{
    ctx->nentries = 0;
    ctx->entries = NULL;
}

void evmap_io_initmap(struct event_io_map* ctx)
{
    evmap_signal_initmap(ctx);
}

void event_changelist_init(struct event_changelist *changelist)
{
    changelist->changes = NULL;
    changelist->changes_size = 0;
    changelist->n_changes = 0;
}

int evthread_make_base_notifiable(struct event_base *base)
{
    //读和写回调函数
    void (*cb)(evutil_socket_t, short, void *) = evthread_notify_drain_default;
    int (*notify)(struct event_base *) = evthread_notify_base_default;

    /* XXXX grab the lock here? */
    if (!base)
        return -1;

    if (base->th_notify_fd[0] >= 0)
        return 0;

#if defined(_EVENT_HAVE_EVENTFD) && defined(_EVENT_HAVE_SYS_EVENTFD_H)
    #ifndef EFD_CLOEXEC
#define EFD_CLOEXEC 0
#endif
base->th_notify_fd[0] = eventfd(0, EFD_CLOEXEC);//返回一个文件描述符 eventfd
if (base->th_notify_fd[0] >= 0) {
evutil_make_socket_closeonexec(base->th_notify_fd[0]);
notify = evthread_notify_base_eventfd;
cb = evthread_notify_drain_eventfd;
}
#endif
#if defined(_EVENT_HAVE_PIPE)
    if (base->th_notify_fd[0] < 0) {
if ((base->evsel->features & EV_FEATURE_FDS)) {
if (pipe(base->th_notify_fd) < 0) {//创建管道
event_warn("%s: pipe", __func__);
} else {
evutil_make_socket_closeonexec(base->th_notify_fd[0]);
evutil_make_socket_closeonexec(base->th_notify_fd[1]);
}
}
}
#endif

#ifdef WIN32
#define LOCAL_SOCKETPAIR_AF AF_INET
#else
#define LOCAL_SOCKETPAIR_AF AF_UNIX
#endif
    if (base->th_notify_fd[0] < 0) {
        if (evutil_socketpair(LOCAL_SOCKETPAIR_AF, SOCK_STREAM, 0,
                              base->th_notify_fd) == -1) {
            event_sock_warn(-1, "%s: socketpair", __func__);
            return (-1);
        } else {
            //调用fcntl函数控制其FD_CLOEXEC
            evutil_make_socket_closeonexec(base->th_notify_fd[0]);
            evutil_make_socket_closeonexec(base->th_notify_fd[1]);
        }
    }

    evutil_make_socket_nonblocking(base->th_notify_fd[0]);

    base->th_notify_fn = notify;

    if (base->th_notify_fd[1] > 0)
        evutil_make_socket_nonblocking(base->th_notify_fd[1]);

    event_assign(&base->th_notify, base, base->th_notify_fd[0],
                 EV_READ|EV_PERSIST, cb, base);

    base->th_notify.ev_flags |= EVLIST_INTERNAL;
    event_priority_set(&base->th_notify, 0);

    return event_add(&base->th_notify, NULL);
}

struct event_base *event_base_new_with_config(const struct event_config *cfg)
{
    int i;
    struct event_base *base;
    int should_check_environment;

    if ((base = mm_calloc(1, sizeof(struct event_base))) == NULL) {
        return NULL;
    }
    detect_monotonic();
    gettime(base, &base->event_tv);
    min_heap_ctor(&base->timeheap);

    TAILQ_INIT(&base->eventqueue);

    base->sig.ev_signal_pair[0] = -1;
    base->sig.ev_signal_pair[1] = -1;
    base->th_notify_fd[0] = -1;
    base->th_notify_fd[1] = -1;


    event_deferred_cb_queue_init(&base->defer_queue);
    //给event_base 延迟队列的通知设置回调函数
    base->defer_queue.notify_fn = notify_base_cbq_callback;
    base->defer_queue.notify_arg = base;
    //给event_base成员设置flags
    if (cfg)
        base->flags = cfg->flags;
    //给event_base io成员初始化
    evmap_io_initmap(&base->io);
    evmap_signal_initmap(&base->sigmap);
    event_changelist_init(&base->changelist);

    base->evbase = NULL;

    should_check_environment =
            !(cfg && (cfg->flags & EVENT_BASE_FLAG_IGNORE_ENV));

    for (i = 0; eventops[i] && !base->evbase; i++) {
        if (cfg != NULL) {
            /* determine if this backend should be avoided */
            //检测cfg给的配置是否与目前eventpos数组的某IO复用匹配
            if (event_config_is_avoided_method(cfg,
                                               eventops[i]->name))
                continue;
            if ((eventops[i]->features & cfg->require_features)
                != cfg->require_features)
                continue;
        }

        /* also obey the environment variables */
        if (should_check_environment &&
            event_is_method_disabled(eventops[i]->name))
            continue;

        base->evsel = eventops[i];
        //假设系统选择的IO复用是epoll则看epoll.c的封装
        base->evbase = base->evsel->init(base);
    }

    if (base->evbase == NULL) {
        event_warnx("%s: no event mechanism available",
                    __func__);
        base->evsel = NULL;
        event_base_free(base);
        return NULL;
    }
    //获取环境变量
    if (evutil_getenv("EVENT_SHOW_METHOD"))
        event_msgx("libevent using: %s", base->evsel->name);

    /* allocate a single active event queue */
    if (event_base_priority_init(base, 1) < 0) {
        event_base_free(base);
        return NULL;
    }

    /* prepare for threading */

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
    if (EVTHREAD_LOCKING_ENABLED() &&
        (!cfg || !(cfg->flags & EVENT_BASE_FLAG_NOLOCK))) {
        int r;
        EVTHREAD_ALLOC_LOCK(base->th_base_lock,
                            EVTHREAD_LOCKTYPE_RECURSIVE);
        base->defer_queue.lock = base->th_base_lock;
        EVTHREAD_ALLOC_COND(base->current_event_cond);
        r = evthread_make_base_notifiable(base);
        if (r<0) {
            event_warnx("%s: Unable to make base notifiable.", __func__);
            event_base_free(base);
            return NULL;
        }
    }
#endif

#ifdef WIN32
    if (cfg && (cfg->flags & EVENT_BASE_FLAG_STARTUP_IOCP))
        event_base_start_iocp(base, cfg->n_cpus_hint);
#endif

    return (base);
}
struct event* min_heap_top(min_heap_t* s) {
    return s->n ? *s->p : 0;
}
static int timeout_next(struct event_base *base, struct timeval **tv_p)
{
    /* Caller must hold th_base_lock */
    struct timeval now;
    struct event *ev;
    struct timeval *tv = *tv_p;
    int res = 0;

    ev = min_heap_top(&base->timeheap);

    if (ev == NULL) {
        /* if no time-based events are active wait for I/O */
        *tv_p = NULL;
        goto out;
    }

    if (gettime(base, &now) == -1) {
        res = -1;
        goto out;
    }

    if (evutil_timercmp(&ev->ev_timeout, &now, <=)) {
        evutil_timerclear(tv);
        goto out;
    }

    evutil_timersub(&ev->ev_timeout, &now, tv);

    EVUTIL_ASSERT(tv->tv_sec >= 0);
    EVUTIL_ASSERT(tv->tv_usec >= 0);
    event_debug(("timeout_next: in %d seconds", (int)tv->tv_sec));

    out:
    return (res);
}
int event_base_loop(struct event_base *base, int flags)
{
    const struct eventop *evsel = base->evsel;
    struct timeval tv;
    struct timeval *tv_p;
    int res, done, retval = 0;

    EVBASE_ACQUIRE_LOCK(base, th_base_lock);

    if (base->running_loop) {
        EVBASE_RELEASE_LOCK(base, th_base_lock);
        return -1;
    }

    base->running_loop = 1;

    clear_time_cache(base);

    if (base->sig.ev_signal_added && base->sig.ev_n_signals_added)
        evsig_set_base(base);

    done = 0;

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
    base->th_owner_id = EVTHREAD_GET_ID();
#endif

    base->event_gotterm = base->event_break = 0;

    //无限RUNNING
    while (!done) {
        base->event_continue = 0;

        /* Terminate the loop if we have been asked to */
        if (base->event_gotterm) {
            break;
        }

        if (base->event_break) {
            break;
        }

        timeout_correct(base, &tv);

        tv_p = &tv;
        if (!N_ACTIVE_CALLBACKS(base) && !(flags & EVLOOP_NONBLOCK)) {
            timeout_next(base, &tv_p);
        } else {
            /*
             * if we have active events, we just poll new events
             * without waiting.
             */
            evutil_timerclear(&tv);
        }

        /* If we have no events, we just exit */
        if (!event_haveevents(base) && !N_ACTIVE_CALLBACKS(base)) {
            event_debug(("%s: no events registered.", __func__));
            retval = 1;
            goto done;
        }

        /* update last old time */
        gettime(base, &base->event_tv);

        clear_time_cache(base);

        //reactor事件调度
        res = evsel->dispatch(base, tv_p);

        if (res == -1) {
            event_debug(("%s: dispatch returned unsuccessfully.",
                    __func__));
            retval = -1;
            goto done;
        }

        update_time_cache(base);

        timeout_process(base);

        if (N_ACTIVE_CALLBACKS(base)) {
            int n = event_process_active(base);
            if ((flags & EVLOOP_ONCE)
                && N_ACTIVE_CALLBACKS(base) == 0
                && n != 0)
                done = 1;
        } else if (flags & EVLOOP_NONBLOCK)
            done = 1;
    }
    event_debug(("%s: asked to terminate loop.", __func__));

    done:
    clear_time_cache(base);
    base->running_loop = 0;

    EVBASE_RELEASE_LOCK(base, th_base_lock);

    return (retval);
}
