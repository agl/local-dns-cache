#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdio.h>

#include "env.h"
#include "exit.h"
#include "scan.h"
#include "strerr.h"
#include "error.h"
#include "ip4.h"
#include "uint16.h"
#include "uint64.h"
#include "socket.h"
#include "dns.h"
#include "taia.h"
#include "byte.h"
#include "roots.h"
#include "fmt.h"
#include "iopause.h"
#include "query.h"
#include "alloc.h"
#include "response.h"
#include "cache.h"
#include "ndelay.h"
#include "log.h"
#include "okclient.h"
#include "droproot.h"
#include "maxclient.h"

static int packetquery(char *buf,unsigned int len,char **q,char qtype[2],char qclass[2],char id[2])
{
  unsigned int pos;
  char header[12];

  errno = error_proto;
  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) return 0;
  if (header[2] & 128) return 0; /* must not respond to responses */
  if (!(header[2] & 1)) return 0; /* do not respond to non-recursive queries */
  if (header[2] & 120) return 0;
  if (header[2] & 2) return 0;
  if (byte_diff(header + 4,2,"\0\1")) return 0;

  pos = dns_packet_getname(buf,len,pos,q); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,qtype,2); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,qclass,2); if (!pos) return 0;
  if (byte_diff(qclass,2,DNS_C_IN) && byte_diff(qclass,2,DNS_C_ANY)) return 0;

  byte_copy(id,2,header);
  return 1;
}


static char myipoutgoing[4];
static char myipincoming[4];
static char buf[1024];
uint64 numqueries = 0;


static int udp53;

static struct udpclient {
  struct query q;
  struct taia start;
  uint64 active; /* query number, if active; otherwise 0 */
  iopause_fd *io;
  char ip[4];
  uint16 port;
  char id[2];
} u[MAXUDP];
int uactive = 0;

void u_drop(int j)
{
  if (!u[j].active) return;
  log_querydrop(&u[j].active);
  u[j].active = 0; --uactive;
}

void u_respond(int j)
{
  if (!u[j].active) return;
  response_id(u[j].id);
  if (response_len > 512) response_tc();
  socket_send4(udp53,response,response_len,u[j].ip,u[j].port);
  log_querydone(&u[j].active,response_len);
  u[j].active = 0; --uactive;
}

void u_new(void)
{
  int j;
  int i;
  struct udpclient *x;
  int len;
  static char *q = 0;
  char qtype[2];
  char qclass[2];

  for (j = 0;j < MAXUDP;++j)
    if (!u[j].active)
      break;

  if (j >= MAXUDP) {
    j = 0;
    for (i = 1;i < MAXUDP;++i)
      if (taia_less(&u[i].start,&u[j].start))
	j = i;
    errno = error_timeout;
    u_drop(j);
  }

  x = u + j;
  taia_now(&x->start);

  len = socket_recv4(udp53,buf,sizeof buf,x->ip,&x->port);
  if (len == -1) return;
  if (len >= sizeof buf) return;
  if (x->port < 1024) if (x->port != 53) return;
  if (!okclient(x->ip)) return;

  if (!packetquery(buf,len,&q,qtype,qclass,x->id)) return;

  x->active = ++numqueries; ++uactive;
  log_query(&x->active,x->ip,x->port,x->id,q,qtype);
  switch(query_start(&x->q,q,qtype,qclass,myipoutgoing)) {
    case -1:
      u_drop(j);
      return;
    case 1:
      u_respond(j);
  }
}


static int tcp53;

struct tcpclient {
  struct query q;
  struct taia start;
  struct taia timeout;
  uint64 active; /* query number or 1, if active; otherwise 0 */
  iopause_fd *io;
  char ip[4]; /* send response to this address */
  uint16 port; /* send response to this port */
  char id[2];
  int tcp; /* open TCP socket, if active */
  int state;
  char *buf; /* 0, or dynamically allocated of length len */
  unsigned int len;
  unsigned int pos;
} t[MAXTCP];
int tactive = 0;

/*
state 1: buf 0; normal state at beginning of TCP connection
state 2: buf 0; have read 1 byte of query packet length into len
state 3: buf allocated; have read pos bytes of buf
state 0: buf 0; handling query in q
state -1: buf allocated; have written pos bytes
*/

void t_free(int j)
{
  if (!t[j].buf) return;
  alloc_free(t[j].buf);
  t[j].buf = 0;
}

void t_timeout(int j)
{
  struct taia now;
  if (!t[j].active) return;
  taia_now(&now);
  taia_uint(&t[j].timeout,10);
  taia_add(&t[j].timeout,&t[j].timeout,&now);
}

void t_close(int j)
{
  if (!t[j].active) return;
  t_free(j);
  log_tcpclose(t[j].ip,t[j].port);
  close(t[j].tcp);
  t[j].active = 0; --tactive;
}

void t_drop(int j)
{
  log_querydrop(&t[j].active);
  errno = error_pipe;
  t_close(j);
}

void t_respond(int j)
{
  if (!t[j].active) return;
  log_querydone(&t[j].active,response_len);
  response_id(t[j].id);
  t[j].len = response_len + 2;
  t_free(j);
  t[j].buf = alloc(response_len + 2);
  if (!t[j].buf) { t_close(j); return; }
  uint16_pack_big(t[j].buf,response_len);
  byte_copy(t[j].buf + 2,response_len,response);
  t[j].pos = 0;
  t[j].state = -1;
}

void t_rw(int j)
{
  struct tcpclient *x;
  char ch;
  static char *q = 0;
  char qtype[2];
  char qclass[2];
  int r;

  x = t + j;
  if (x->state == -1) {
    r = write(x->tcp,x->buf + x->pos,x->len - x->pos);
    if (r <= 0) { t_close(j); return; }
    x->pos += r;
    if (x->pos == x->len) {
      t_free(j);
      x->state = 1; /* could drop connection immediately */
    }
    return;
  }

  r = read(x->tcp,&ch,1);
  if (r == 0) { errno = error_pipe; t_close(j); return; }
  if (r < 0) { t_close(j); return; }

  if (x->state == 1) {
    x->len = (unsigned char) ch;
    x->len <<= 8;
    x->state = 2;
    return;
  }
  if (x->state == 2) {
    x->len += (unsigned char) ch;
    if (!x->len) { errno = error_proto; t_close(j); return; }
    x->buf = alloc(x->len);
    if (!x->buf) { t_close(j); return; }
    x->pos = 0;
    x->state = 3;
    return;
  }

  if (x->state != 3) return; /* impossible */

  x->buf[x->pos++] = ch;
  if (x->pos < x->len) return;

  if (!packetquery(x->buf,x->len,&q,qtype,qclass,x->id)) { t_close(j); return; }

  x->active = ++numqueries;
  log_query(&x->active,x->ip,x->port,x->id,q,qtype);
  switch(query_start(&x->q,q,qtype,qclass,myipoutgoing)) {
    case -1:
      t_drop(j);
      return;
    case 1:
      t_respond(j);
      return;
  }
  t_free(j);
  x->state = 0;
}

void t_new(void)
{
  int i;
  int j;
  struct tcpclient *x;

  for (j = 0;j < MAXTCP;++j)
    if (!t[j].active)
      break;

  if (j >= MAXTCP) {
    j = 0;
    for (i = 1;i < MAXTCP;++i)
      if (taia_less(&t[i].start,&t[j].start))
	j = i;
    errno = error_timeout;
    if (t[j].state == 0)
      t_drop(j);
    else
      t_close(j);
  }

  x = t + j;
  taia_now(&x->start);

  x->tcp = socket_accept4(tcp53,x->ip,&x->port);
  if (x->tcp == -1) return;
  if (x->port < 1024) if (x->port != 53) { close(x->tcp); return; }
  if (!okclient(x->ip)) { close(x->tcp); return; }
  if (ndelay_on(x->tcp) == -1) { close(x->tcp); return; } /* Linux bug */

  x->active = 1; ++tactive;
  x->state = 1;
  t_timeout(j);

  log_tcpopen(x->ip,x->port);
}


iopause_fd io[3 + MAXUDP + MAXTCP];
iopause_fd *udp53io;
iopause_fd *tcp53io;

static void doit(void)
{
  int j;
  struct taia deadline;
  struct taia stamp;
  int iolen;
  int r;

  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);

    iolen = 0;

    udp53io = io + iolen++;
    udp53io->fd = udp53;
    udp53io->events = IOPAUSE_READ;

    tcp53io = io + iolen++;
    tcp53io->fd = tcp53;
    tcp53io->events = IOPAUSE_READ;

    for (j = 0;j < MAXUDP;++j)
      if (u[j].active) {
	u[j].io = io + iolen++;
	query_io(&u[j].q,u[j].io,&deadline);
      }
    for (j = 0;j < MAXTCP;++j)
      if (t[j].active) {
	t[j].io = io + iolen++;
	if (t[j].state == 0)
	  query_io(&t[j].q,t[j].io,&deadline);
	else {
	  if (taia_less(&t[j].timeout,&deadline)) deadline = t[j].timeout;
	  t[j].io->fd = t[j].tcp;
	  t[j].io->events = (t[j].state > 0) ? IOPAUSE_READ : IOPAUSE_WRITE;
	}
      }

    iopause(io,iolen,&deadline,&stamp);

    for (j = 0;j < MAXUDP;++j)
      if (u[j].active) {
	r = query_get(&u[j].q,u[j].io,&stamp);
	if (r == -1) u_drop(j);
	if (r == 1) u_respond(j);
      }

    for (j = 0;j < MAXTCP;++j)
      if (t[j].active) {
	if (t[j].io->revents)
	  t_timeout(j);
	if (t[j].state == 0) {
	  r = query_get(&t[j].q,t[j].io,&stamp);
	  if (r == -1) t_drop(j);
	  if (r == 1) t_respond(j);
	}
	else
	  if (t[j].io->revents || taia_less(&t[j].timeout,&stamp))
	    t_rw(j);
      }

    if (udp53io)
      if (udp53io->revents)
	u_new();

    if (tcp53io)
      if (tcp53io->revents)
	t_new();
  }
}
  
#define FATAL "dnscache: fatal: "

char seed[128];

int main(int argc, char **argv)
{
  char *x;
  unsigned long cachesize;

  const char *opt_listen_ip = "127.0.0.1",
             *opt_send_ip = "0.0.0.0",
             *opt_port = "53",
             *opt_cache_size = "1000000",
             *opt_data_limit = "3000000",
             *opt_config_dir = "/etc/local-dns-cache";
  char opt_hide_ttl = 0,
       opt_forward_only = 0;

  static const struct option options[] = {
    {"listen-ip", 1 /* has argument */, 0, 0},
    {"send-ip", 1 /* has argument */, 0, 0},
    {"port", 1 /* has argument */, 0, 0},
    {"cache-size", 1 /* has argument */, 0, 0},
    {"config-dir", 1 /* has argument */, 0, 0},
    /* If you add anything above here, update |num_arguments_with_options|
     * and |argument_option_values| */
    {"hide-ttl", 0, 0, 0},
    {"forward-only", 0, 0, 0},

    {"help", 0, 0, 0},
    {0, 0, 0, 0},
  };

  static const unsigned num_arguments_with_options = 5;

  /* This array is parallel to the first |num_arguments_with_options| elements
   * of |options| and contains the char pointers which will receive the option
   * arguments */
  const char **argument_option_values[] = {
    &opt_listen_ip,
    &opt_send_ip,
    &opt_port,
    &opt_cache_size,
    &opt_config_dir,
  };

  /* This array is parallel to the last $arraysize(options) -
   * num_arguments_with_options$ elements of |options|. It contains pointers to
   * the bool flags which are set if we see the corresponding argument */
  char *argument_option_flags[] = {
    &opt_hide_ttl,
    &opt_forward_only,
  };

  for (;;) {
    int option_index = 0;
    const int c = getopt_long(argc, argv, "h", options, &option_index);

    if (c == -1)
      break;

    if (c)
      strerr_die2x(111,FATAL,"getopt returned unknown value");

    if (c == 'h' || c == 0 && strcmp(options[option_index].name, "help") == 0) {
      fprintf(stderr, "local-dns-cache:\n\n"
                      "  --listen-ip: the IP address to listen on (%s)\n"
                      "  --send-ip: the IP address to send on (%s)\n"
                      "  --config-dir: the location of the configuration (%s)\n"
                      "  --port: the port number to bind to (%s)\n"
                      "  --cache-size: the size (in bytes) of the cache (%s)\n"
                      "  --hide-ttl: if set, always return a TTL of 0\n"
                      "  --forward-only: if set, make recursive queries\n",
              opt_listen_ip, opt_send_ip, opt_config_dir, opt_port,
              opt_cache_size);
      return 1;
    }

    if (option_index < num_arguments_with_options)
      *argument_option_values[option_index] = optarg;
    else
      *argument_option_flags[option_index - num_arguments_with_options] = 1;
  }

  if (!ip4_scan(opt_listen_ip,myipincoming))
    strerr_die3x(111,FATAL,"unable to parse IP address ", opt_listen_ip);

  unsigned long port = 0;
  scan_ulong(opt_port, &port);
  if (port > 65535 || port == 0)
    strerr_die3x(111, FATAL, "unable to parse port number ", opt_port);

  udp53 = socket_udp();
  if (udp53 == -1)
    strerr_die2sys(111,FATAL,"unable to create UDP socket: ");
  if (socket_bind4_reuse(udp53,myipincoming,port) == -1)
    strerr_die2sys(111,FATAL,"unable to bind UDP socket: ");

  tcp53 = socket_tcp();
  if (tcp53 == -1)
    strerr_die2sys(111,FATAL,"unable to create TCP socket: ");
  if (socket_bind4_reuse(tcp53,myipincoming,port) == -1)
    strerr_die2sys(111,FATAL,"unable to bind TCP socket: ");

  // FIXME(agl): work when run as root
  // droproot(FATAL);

  socket_tryreservein(udp53,131072);

  const int urandomfd = open("/dev/urandom", O_RDONLY);
  if (urandomfd < 0)
    strerr_die2sys(111, FATAL, "unable to open /dev/urandom: ");
  if (read(urandomfd,seed,sizeof seed) != sizeof(seed))
    strerr_die2sys(111, FATAL, "unable to read /dev/urandom: ");
  dns_random_init(seed);
  close(urandomfd);

  if (!ip4_scan(opt_send_ip, myipoutgoing))
    strerr_die3x(111,FATAL,"unable to parse IP address ", opt_send_ip);

  scan_ulong(opt_cache_size,&cachesize);
  if (!cache_init(cachesize))
    strerr_die3x(111,FATAL,"not enough memory for cache of size ", opt_cache_size);

  if (opt_hide_ttl)
    response_hidettl();
  if (opt_forward_only)
    query_forwardonly();

  if (chdir(opt_config_dir))
    strerr_die2sys(111, FATAL, "unable to change to config directory: ");

  if (!roots_init())
    strerr_die2sys(111,FATAL,"unable to read servers: ");

  if (socket_listen(tcp53,20) == -1)
    strerr_die2sys(111,FATAL,"unable to listen on TCP socket: ");

  log_startup();
  doit();
}
