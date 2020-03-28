//
// Created by 1655664358@qq.com on 2020/3/26.
//
#include "libevent_database.h"
#include "event_macro.h"
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

int evutil_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    struct _timeb tb;

    if (tv == NULL)
        return -1;
    //获取到毫秒级的时间
    _ftime(&tb);
    tv->tv_sec = (long) tb.time;
    tv->tv_usec = ((int) tb.millitm) * 1000;
    return 0;
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
			//给tv变量两赋上时间精确到纳秒
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
/**
 *  创建一个事件处理器
 * @param ev 事件处理器结构体
 * @param base event_base
 * @param fd  文件描述符|信号数值|-1表示定时事件
 * @param events 读写事件|信号事件|0定时事件
 * @param callback 事件的回调函数
 * @param arg 回调函数的参数
 * @return
 */
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

    //信号事件
    if (events & EV_SIGNAL) {
        if ((events & (EV_READ|EV_WRITE)) != 0) {
            event_warnx("%s: EV_SIGNAL is not compatible with "
                        "EV_READ or EV_WRITE", __func__);
            return -1;
        }
        ev->ev_closure = EV_CLOSURE_SIGNAL;
    } else {
        //持续性事件
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
int evmap_io_add(struct event_base *base, evutil_socket_t fd, struct event *ev)
{
    const struct eventop *evsel = base->evsel;
    //io事件处理器数组
    struct event_io_map *io = &base->io;

    struct evmap_io *ctx = NULL;
    int nread, nwrite, retval = 0;
    short res = 0, old = 0;
    struct event *old_ev;

    EVUTIL_ASSERT(fd == ev->ev_fd);

    if (fd < 0)
        return 0;

#ifndef EVMAP_USE_HT
    //创建I/O事件处理器数组
    if (fd >= io->nentries) {
        if (evmap_make_space(io, fd, sizeof(struct evmap_io *)) == -1)
            return (-1);
    }
#endif

    /**
     *
#define GET_SIGNAL_SLOT_AND_CTOR(x, map, slot, type, ctor, fdinfo_len)
if ((map)->entries[slot] == NULL) {
(map)->entries[slot] =	mm_calloc(1,sizeof(struct type)+fdinfo_len);
(ctor)((struct type *)(map)->entries[slot]);
(x) = (struct type *)((map)->entries[slot]);

#define GET_IO_SLOT_AND_CTOR(x,map,slot,type,ctor,fdinfo_len) GET_SIGNAL_SLOT_AND_CTOR(x,map,slot,type,ctor,fdinfo_len)
     */

    //文件描述符=evmap_io内存地址
    //io->entries[fd] = mm_calloc(1,sizeof(struct evmap_io)+fdinfo_len)
    //ctx = (struct evmap_io *)(io->entries[fd])
    //ctx 操作是event_base->io成员【其实它是个数组】
    //每添加一个io添加一个成员在event_base->io数组中
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
        //向epoll或是其它IO复用函数【我这里默认以epoll使用】内核事件表中注册读写就绪事件
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

int evmap_make_space(struct event_signal_map *map, int slot, int msize)
{
    if (map->nentries <= slot) {
        int nentries = map->nentries ? map->nentries : 32;
        void **tmp;

        while (nentries <= slot)
            nentries <<= 1;

        tmp = (void **)mm_realloc(map->entries, nentries * msize);
        if (tmp == NULL)
            return (-1);

        memset(&tmp[map->nentries], 0,
               (nentries - map->nentries) * msize);

        map->nentries = nentries;
        map->entries = tmp;
    }

    return (0);
}

int evmap_make_space(struct event_signal_map *map, int slot, int msize)
{
    //netries=0<信号数值
    if (map->nentries <= slot) {
        int nentries = map->nentries ? map->nentries : 32;
        void **tmp;
        //linux 信号只有32个有效，剩下的32个是扩展的信号并不用
        //0<32
        //假设信号为SIGINT 2
        while (nentries <= slot)
            nentries <<= 1;//数据左移操作  如1左移 0000 0001  0000 0010 为2

            //entries是1个数组  nentries=32*申请好的内容空间 【动态扩展数组内存大小】
        tmp = (void **)mm_realloc(map->entries, nentries * msize);
        if (tmp == NULL)
            return (-1);

        //初始化数组
        memset(&tmp[map->nentries], 0,
               (nentries - map->nentries) * msize);

        //2
        map->nentries = nentries;
        map->entries = tmp;
    }

    return (0);
}


void evmap_signal_init(struct evmap_signal *entry)
{
    TAILQ_INIT(&entry->events);
}

/**
 * sig 信号数值
 * ev 信号事件处理器【一般经过event_new处理】
 */
int evmap_signal_add(struct event_base *base, int sig, struct event *ev)
{
    /**
     *信号事件处理器添加的动作得到的数据结构大概是这样
     * struct event_base{
     *          struct event_signal_map sigmap{
     *                  void **entries[sigNum] = struct evmap_signal {
                                                    struct event_list events=struct event_list {
                                                        struct event *tqh_first;
                                                        struct event **tqh_last=struct event *ev[信号事件处理器封装好的数据];
                                                    }
                                                };
	                    int nentries=sigNum;
     *          }
     * }
     */
    const struct eventop *evsel = base->evsigsel;
    //信号事件映射数组
    struct event_signal_map *map = &base->sigmap;//对map的操作就是操作base->sigmap
    //信号事件队列映射
    struct evmap_signal *ctx = NULL;

    //nentries = 0 初始化时为0
    //信号值一般都大于0的
    if (sig >= map->nentries) {
        if (evmap_make_space(//给map申请指定大小的内存【数组】
                map, sig, sizeof(struct evmap_signal *)) == -1)
            return (-1);
    }
    //ctx 信号事件队列
    //map 信号事件数组
    //sig 信号数值
    //最终初始化为：ctx=map->entries[信号值] = (struct evmap_signal*)内存地址
    GET_SIGNAL_SLOT_AND_CTOR(ctx, map, sig, evmap_signal, evmap_signal_init,
                             base->evsigsel->fdinfo_len);

    //第一次为空
    if (TAILQ_EMPTY(&ctx->events)) {
        //此处需要看初始化时做的事情【有道笔记图】
        if (evsel->add(base, ev->ev_fd, 0, EV_SIGNAL, NULL)
            == -1)
            return (-1);
    }
    //将信号事件处理器插入到链表中
    TAILQ_INSERT_TAIL(&ctx->events, ev, ev_signal_next);

    return (1);
}

void min_heap_shift_up_(min_heap_t* s, unsigned hole_index, struct event* e)
{
    unsigned parent = (hole_index - 1) / 2;
    while (hole_index && min_heap_elem_greater(s->p[parent], e))
    {
        (s->p[hole_index] = s->p[parent])->ev_timeout_pos.min_heap_idx = hole_index;
        hole_index = parent;
        parent = (hole_index - 1) / 2;
    }
    (s->p[hole_index] = e)->ev_timeout_pos.min_heap_idx = hole_index;
}

int min_heap_push(min_heap_t* s, struct event* e)
{
    if (min_heap_reserve(s, s->n + 1))
        return -1;
    min_heap_shift_up_(s, s->n++, e);
    return 0;
}
static void event_queue_insert(struct event_base *base, struct event *ev, int queue)
{
    EVENT_BASE_ASSERT_LOCKED(base);

    if (ev->ev_flags & queue) {
        /* Double insertion is possible for active events */
        if (queue & EVLIST_ACTIVE)
            return;

        event_errx(1, "%s: %p(fd "EV_SOCK_FMT") already on queue %x", __func__,
                   ev, EV_SOCK_ARG(ev->ev_fd), queue);
        return;
    }

    if (~ev->ev_flags & EVLIST_INTERNAL)
        base->event_count++;

    ev->ev_flags |= queue;
    switch (queue) {
        case EVLIST_INSERTED:
            TAILQ_INSERT_TAIL(&base->eventqueue, ev, ev_next);
            break;
        case EVLIST_ACTIVE:
            base->event_count_active++;
            TAILQ_INSERT_TAIL(&base->activequeues[ev->ev_pri],
                              ev,ev_active_next);
            break;
        case EVLIST_TIMEOUT: {
            if (is_common_timeout(&ev->ev_timeout, base)) {
                struct common_timeout_list *ctl =
                        get_common_timeout_list(base, &ev->ev_timeout);
                insert_common_timeout_inorder(ctl, ev);
            } else
                min_heap_push(&base->timeheap, ev);
            break;
        }
        default:
            event_errx(1, "%s: unknown queue %x", __func__, queue);
    }
}

int event_add_internal(struct event *ev, const struct timeval *tv,int tv_is_absolute)
{
    struct event_base *base = ev->ev_base;
    int res = 0;
    int notify = 0;

    EVENT_BASE_ASSERT_LOCKED(base);
    _event_debug_assert_is_setup(ev);

    event_debug((
                        "event_add: event: %p (fd "EV_SOCK_FMT"), %s%s%scall %p",
                                ev,
                                EV_SOCK_ARG(ev->ev_fd),
                                ev->ev_events & EV_READ ? "EV_READ " : " ",
                                ev->ev_events & EV_WRITE ? "EV_WRITE " : " ",
                                tv ? "EV_TIMEOUT " : " ",
                                ev->ev_callback));

    EVUTIL_ASSERT(!(ev->ev_flags & ~EVLIST_ALL));


    if (tv != NULL && !(ev->ev_flags & EVLIST_TIMEOUT)) {
        if (min_heap_reserve(&base->timeheap,
                             1 + min_heap_size(&base->timeheap)) == -1)
            return (-1);  /* ENOMEM == errno */
    }

    //与多线程同步相关的配置【暂且不管】
#ifndef _EVENT_DISABLE_THREAD_SUPPORT
    if (base->current_event == ev && (ev->ev_events & EV_SIGNAL)
        && !EVBASE_IN_THREAD(base)) {
        ++base->current_event_waiters;
        EVTHREAD_COND_WAIT(base->current_event_cond, base->th_base_lock);
    }
#endif

    if ((ev->ev_events & (EV_READ|EV_WRITE|EV_SIGNAL)) &&
        !(ev->ev_flags & (EVLIST_INSERTED|EVLIST_ACTIVE))) {
        if (ev->ev_events & (EV_READ|EV_WRITE))//IO事件
            res = evmap_io_add(base, ev->ev_fd, ev);
        else if (ev->ev_events & EV_SIGNAL)//信号事件
            res = evmap_signal_add(base, (int)ev->ev_fd, ev);//event_base 信号数值  信号事件处理器
        if (res != -1)
            event_queue_insert(base, ev, EVLIST_INSERTED);
        if (res == 1) {
            /* evmap says we need to notify the main thread. */
            notify = 1;
            res = 0;
        }
    }

    //定时事件在这里添加
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

int event_add(struct event *ev, const struct timeval *tv)
{
    int res;

    if (EVUTIL_FAILURE_CHECK(!ev->ev_base)) {
        event_warnx("%s: event has no event_base set.", __func__);
        return -1;
    }

    EVBASE_ACQUIRE_LOCK(ev->ev_base, th_base_lock);

    res = event_add_internal(ev, tv, 0);

    EVBASE_RELEASE_LOCK(ev->ev_base, th_base_lock);

    return (res);
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


    //给指定的文件IO创建事件处理器
    event_assign(&base->th_notify, base, base->th_notify_fd[0],
                 EV_READ|EV_PERSIST, cb, base);

    base->th_notify.ev_flags |= EVLIST_INTERNAL;
    event_priority_set(&base->th_notify, 0);

    return event_add(&base->th_notify, NULL);
}


static int evthread_notify_base_eventfd(struct event_base *base)
{
    ev_uint64_t msg = 1;
    int r;
    do {
        r = write(base->th_notify_fd[0], (void*) &msg, sizeof(msg));
    } while (r < 0 && errno == EAGAIN);

    return (r < 0) ? -1 : 0;
}
struct event_base *event_base_new_with_config(const struct event_config *cfg)
{
    int i;
    struct event_base *base;
    int should_check_environment;

    //给event_base赋初始内存值
    if ((base = mm_calloc(1, sizeof(struct event_base))) == NULL) {
        return NULL;
    }
    //测试是否支持获取系统时间
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
//传递cfg参数且支持线程时
#ifndef _EVENT_DISABLE_THREAD_SUPPORT
    if (EVTHREAD_LOCKING_ENABLED() &&
        (!cfg || !(cfg->flags & EVENT_BASE_FLAG_NOLOCK))) {
        int r;
        EVTHREAD_ALLOC_LOCK(base->th_base_lock,
                            EVTHREAD_LOCKTYPE_RECURSIVE);
        base->defer_queue.lock = base->th_base_lock;
        EVTHREAD_ALLOC_COND(base->current_event_cond);
        //添加内部的I/O事件处理器【epoll内核注册并监听】
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
/**
 * 创建一个事件处理器
 * event_base
 * 文件描述符|信号数值
 * events 事件
 * cb 回调函数
 * arg 参数
 */
struct event * event_new(struct event_base *base, evutil_socket_t fd, short events, void (*cb)(evutil_socket_t, short, void *), void *arg)
{
    //定义事件处理器变量
    struct event *ev;
    ev = mm_malloc(sizeof(struct event));
    if (ev == NULL)
        return (NULL);
    //把信号数值/文件描述符，监听事件，回调函数，回调函数的参数保存
    if (event_assign(ev, base, fd, events, cb, arg) < 0) {
        mm_free(ev);
        return (NULL);
    }

    return (ev);
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

        //reactor事件调度 有事件就绪就会把就绪的事件处理器全部插入请求队列中
        res = evsel->dispatch(base, tv_p);

        if (res == -1) {
            event_debug(("%s: dispatch returned unsuccessfully.",
                    __func__));
            retval = -1;
            goto done;
        }

        update_time_cache(base);

        timeout_process(base);

        //检测是否有就绪的事件
        if (N_ACTIVE_CALLBACKS(base)) {
            //处理事件处理器
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
