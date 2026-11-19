/*
 * uvbridge.c — drive luv's libuv event loop from nginx's event loop.
 *
 * Compiled into luv.so by the luv-uvbridge patch (see patches/). It adds
 * three functions to the luv table:
 *
 *   uv.bridge_attach([tick_ms])  start the pump for this worker (default 10ms)
 *   uv.bridge_detach()          stop the pump
 *   uv.bridge_stats()           -> attached, pump_count, fd_wakeups, tick_wakeups
 *
 * Background
 * ----------
 * libuv's loop is an epoll/kqueue wrapper. Its backend fd
 * (uv_backend_fd()) becomes readable whenever libuv has pending I/O.
 * nginx's event loop (ngx_process_events_and_timers) never wakes up for
 * that fd on its own, so libuv handles created via luv only make progress
 * while some Lua code blocks in uv.run() — which stalls the worker
 * (openresty/lua-nginx-module#2396).
 *
 * This bridge registers the backend fd as an ordinary nginx read event.
 * nginx's own epoll_wait then notices the libuv activity and the handler
 * runs uv_run(loop, UV_RUN_NOWAIT), dispatching libuv's Lua callbacks on
 * the worker thread. A periodic nginx timer (the tick) covers libuv
 * timers/check/idle handles, which do not make the backend fd readable.
 *
 * Consequences and constraints:
 *  - The pump runs on nginx's worker thread. Libuv Lua callbacks execute
 *    inline and must NOT yield (a coroutine.yield() inside a libuv
 *    callback is a LuaJIT error). Spawn a light thread instead.
 *  - Nothing else may run the same loop (no uv.run() from Lua).
 *  - A single worker, a single luv state (the main one from
 *    init_worker_by_lua) is the supported configuration.
 *
 * The backend fd is libuv's epoll fd. We deliberately do NOT take a
 * connection from nginx's pool, so nginx never closes it. On detach the
 * epoll registration is removed before libuv closes the loop.
 */


/* Must precede all includes: nginx's own build defines this via its
 * generated config (exposes struct in6_pktinfo in <netinet/in.h>). */
#define _GNU_SOURCE

#include "luv.h"

#include <lua.h>
#include <lauxlib.h>
#include <uv.h>

/* Platform headers that nginx's own build picks up via its generated
 * auto-headers; needed by ngx_event_udp.h (struct in6_addr et al). */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_timer.h>

/* Exported by luv.c (LUALIB_API) */
extern uv_loop_t *luv_loop(lua_State *L);


static uv_loop_t  *bridge_loop;
static ngx_int_t   bridge_active;
static ngx_msec_t  bridge_tick;

static uint64_t    pump_count;
static uint64_t    fd_wakeups;
static uint64_t    tick_wakeups;

/*
 * Dummy connection holding the backend fd. c->read/c->write must be valid
 * because ngx_epoll_add_event() inspects the opposite event to decide
 * EPOLL_CTL_ADD vs EPOLL_CTL_MOD.
 */
static ngx_connection_t  bridge_conn;
static ngx_event_t       bridge_read_ev;
static ngx_event_t       bridge_write_ev;
static ngx_event_t       bridge_timer_ev;


static void
bridge_pump(void)
{
    uv_run(bridge_loop, UV_RUN_NOWAIT);
    pump_count++;
}


static void
bridge_read_handler(ngx_event_t *ev)
{
    fd_wakeups++;
    bridge_pump();
}


static void
bridge_tick_handler(ngx_event_t *ev)
{
    tick_wakeups++;
    bridge_pump();

    if (bridge_active) {
        ngx_add_timer(&bridge_timer_ev, bridge_tick);
    }
}


int
luv_bridge_attach(lua_State *L)
{
    ngx_int_t  tick;
    int        fd;

    if (bridge_active) {
        return luaL_error(L, "uvbridge: already attached");
    }

    tick = (ngx_int_t) luaL_optinteger(L, 1, 10);
    if (tick < 1) {
        return luaL_error(L, "uvbridge: tick must be >= 1 ms");
    }

    bridge_loop = luv_loop(L);
    if (bridge_loop == NULL) {
        return luaL_error(L, "uvbridge: luv loop not initialized");
    }

    fd = uv_backend_fd(bridge_loop);
    if (fd < 0) {
        return luaL_error(L, "uvbridge: uv_backend_fd failed");
    }

    pump_count = 0;
    fd_wakeups = 0;
    tick_wakeups = 0;

    ngx_memzero(&bridge_conn, sizeof(bridge_conn));
    ngx_memzero(&bridge_read_ev, sizeof(bridge_read_ev));
    ngx_memzero(&bridge_write_ev, sizeof(bridge_write_ev));
    ngx_memzero(&bridge_timer_ev, sizeof(bridge_timer_ev));

    bridge_conn.fd = fd;
    bridge_conn.log = ngx_cycle->log;
    bridge_conn.read = &bridge_read_ev;
    bridge_conn.write = &bridge_write_ev;

    bridge_read_ev.data = &bridge_conn;
    bridge_read_ev.handler = bridge_read_handler;
    bridge_read_ev.log = ngx_cycle->log;

    if (ngx_add_event(&bridge_read_ev, NGX_READ_EVENT, 0) != NGX_OK) {
        return luaL_error(L, "uvbridge: ngx_add_event(NGX_READ_EVENT) failed");
    }

    bridge_timer_ev.data = &bridge_conn;
    bridge_timer_ev.handler = bridge_tick_handler;
    bridge_timer_ev.log = ngx_cycle->log;

    bridge_tick = (ngx_msec_t) tick;
    ngx_add_timer(&bridge_timer_ev, bridge_tick);

    bridge_active = 1;

    return 0;
}


int
luv_bridge_detach(lua_State *L)
{
    if (!bridge_active) {
        return 0;
    }

    /*
     * Stop the tick before removing the fd event; neither may re-arm
     * the other from this point on.
     */
    bridge_active = 0;

    if (bridge_timer_ev.timer_set) {
        ngx_del_timer(&bridge_timer_ev);
    }

    if (bridge_read_ev.active) {
        ngx_del_event(&bridge_read_ev, NGX_READ_EVENT, 0);
    }

    bridge_loop = NULL;

    return 0;
}


int
luv_bridge_stats(lua_State *L)
{
    lua_pushinteger(L, bridge_active);
    lua_pushinteger(L, (lua_Integer) pump_count);
    lua_pushinteger(L, (lua_Integer) fd_wakeups);
    lua_pushinteger(L, (lua_Integer) tick_wakeups);
    return 4;
}
