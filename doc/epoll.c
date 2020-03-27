//
// Created by 1655664358@qq.com on 2020/3/27.
//

static int epoll_nochangelist_add(struct event_base *base, evutil_socket_t fd,short old, short events, void *p)
{
    struct event_change ch;
    ch.fd = fd;
    ch.old_events = old;
    ch.read_change = ch.write_change = 0;
    if (events & EV_WRITE)
        ch.write_change = EV_CHANGE_ADD |
                          (events & EV_ET);
    if (events & EV_READ)
        ch.read_change = EV_CHANGE_ADD |
                         (events & EV_ET);

    return epoll_apply_one_change(base, base->evbase, &ch);
}

static int epoll_nochangelist_del(struct event_base *base, evutil_socket_t fd,short old, short events, void *p)
{
    struct event_change ch;
    ch.fd = fd;
    ch.old_events = old;
    ch.read_change = ch.write_change = 0;
    if (events & EV_WRITE)
        ch.write_change = EV_CHANGE_DEL;
    if (events & EV_READ)
        ch.read_change = EV_CHANGE_DEL;

    return epoll_apply_one_change(base, base->evbase, &ch);
}

static int epoll_dispatch(struct event_base *base, struct timeval *tv)
{
    struct epollop *epollop = base->evbase;
    struct epoll_event *events = epollop->events;
    int i, res;
    long timeout = -1;

    if (tv != NULL) {
        timeout = evutil_tv_to_msec(tv);
        if (timeout < 0 || timeout > MAX_EPOLL_TIMEOUT_MSEC) {
            /* Linux kernels can wait forever if the timeout is
             * too big; see comment on MAX_EPOLL_TIMEOUT_MSEC. */
            timeout = MAX_EPOLL_TIMEOUT_MSEC;
        }
    }

    epoll_apply_changes(base);
    event_changelist_remove_all(&base->changelist, base);

    EVBASE_RELEASE_LOCK(base, th_base_lock);

    //epoll内核事件表
    //events epoll_wait内有就绪队列事件时，会复制给events
    //nevents 初始值是32
    //timeout超时时间 如果有时间  阻塞到时间后就会返回
    res = epoll_wait(epollop->epfd, events, epollop->nevents, timeout);

    EVBASE_ACQUIRE_LOCK(base, th_base_lock);

    //没有就绪的文件描述符
    if (res == -1) {
        if (errno != EINTR) {
            event_warn("epoll_wait");
            return (-1);
        }

        return (0);
    }

    event_debug(("%s: epoll_wait reports %d", __func__, res));
    EVUTIL_ASSERT(res <= epollop->nevents);

    //开始循环处理就绪的文件描述符
    for (i = 0; i < res; i++) {
        int what = events[i].events;//取出事件
        short ev = 0;//保存事件的初始变量

        if (what & (EPOLLHUP|EPOLLERR)) {
            ev = EV_READ | EV_WRITE;
        } else {
            if (what & EPOLLIN)
                ev |= EV_READ;
            if (what & EPOLLOUT)
                ev |= EV_WRITE;
        }

        if (!ev)
            continue;

        evmap_io_active(base, events[i].data.fd, ev | EV_ET);
    }

    if (res == epollop->nevents && epollop->nevents < MAX_NEVENT) {
        /* We used all of the event space this time.  We should
           be ready for more events next time. */
        int new_nevents = epollop->nevents * 2;
        struct epoll_event *new_events;

        new_events = mm_realloc(epollop->events,
                                new_nevents * sizeof(struct epoll_event));
        if (new_events) {
            epollop->events = new_events;
            epollop->nevents = new_nevents;
        }
    }

    return (0);
}