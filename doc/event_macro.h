//
// Created by 1655664358@qq.com on 2020/3/28.
//

#ifndef LIBEVENT_EVENT_MACRO_H
#define LIBEVENT_EVENT_MACRO_H

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
#define CLOCK_SYNC_INTERVAL -1
#define mm_calloc(count, size) event_mm_calloc_((count), (size))
#define EVUTIL_UNLIKELY(p) (p)


#define EVTHREAD_ALLOC_LOCK(lockvar, locktype)		\
	((lockvar) = _evthread_lock_fns.alloc ?		\
	    _evthread_lock_fns.alloc(locktype) : NULL)

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


#define	evutil_timersub(tvp, uvp, vvp)					\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
#endif //LIBEVENT_EVENT_MACRO_H
