#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include <time.h>
#ifdef __WIN32__
# define _WIN32_WINNT 0x0501	/* Windows XP/2003 or higher */
# include <winsock2.h>
# include <ws2tcpip.h>
# include "lib/sysexits.h"
#else
# include <sysexits.h>
# include <unistd.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/time.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <netdb.h>
#endif

#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

#define VERSION_STRING "0.2"

const char *_progname;

static struct option long_options[] = {
  { "help",        0, 0, 'h' },
  { "version",     0, 0, 'V' },
  { "port",        1, 0, 'p' },
  { "address",     1, 0, 'a' },
  { "timeout",     1, 0, 't' },
  { "foreground",  0, 0, 'F' },
  { "pidfile",     1, 0, 'P' },
  { 0, 0, 0, 0 }
};
static const char short_options[] = "hVp:a:t:FP:";

static void usage(void)
{
    fprintf(stderr, "Usage: %s [options]\n"
	    "  --help         -h  Print this help\n"
	    "  --version      -V  Print current version\n"
	    "  --fd           -f  Pass in a socket file descriptor\n"
	    "  --port         -p  Specify port to listen on\n"
	    "  --address      -a  Specify local address to listen on\n"
	    "  --timeout      -t  Timeout before dropping a client\n"
	    "  --foreground   -F  Run in the foreground\n"
	    "  --pidfile      -P  Write the process ID to a file\n"
	    , _progname);
}

struct opts {
    const char *address;
    const char *pidfile;
    unsigned int port;
    unsigned int timeout;
    bool foreground;
} opt = {
    .address    = NULL,
    .pidfile    = NULL,
    .port       = 231,
    .timeout    = 900,
    .foreground = false,
};


union sock_addr {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
#if 0 /* HAVE_IPV6 */
    struct sockaddr_in6 sin6;
#endif
};

struct ipx_addr {
    uint32_t network;
    uint32_t ip_addr;
    uint16_t ip_port;
} __attribute__((packed));

static inline bool is_ipx_null(const struct ipx_addr *addr)
{
    return addr->ip_addr == 0 && addr->ip_port == 0;
}
static inline bool is_ipx_bcst(const struct ipx_addr *addr)
{
    return addr->ip_addr == 0xffffffff && addr->ip_port == 0xffff;
}

struct ipx_client {
    struct ipx_client *next, *prev;
    time_t last_seen;
    struct ipx_addr ipx;
    struct sockaddr_in sin;
};

static struct ipx_client client_head =
{
    .next = &client_head,
    .prev = &client_head,
};

struct ipx_header {
    uint16_t checksum;
    uint16_t length;
    uint8_t  transcontrol;
    uint8_t  ptype;
    struct ipx_addr dst_addr;
    uint16_t dst_sock;
    struct ipx_addr src_addr;
    uint16_t src_sock;
}  __attribute__((packed));

/*
 * Simple timeout to make sure that stale clients don't hog memory
 * indefinitely due to no activity at all.  Note that there is no
 * point to run the timeout if there are no currently registered
 * clients, so disable the timeout in that case so that an idle server
 * can consume zero CPU resources.
 */

static void enable_timeout(int fd)
{
    struct timeval timeout;

    timeout.tv_sec  = opt.timeout;
    timeout.tv_usec = 0;

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout, sizeof timeout);
}

static void disable_timeout(int fd)
{
    struct timeval timeout;

    timeout.tv_sec  = 0;
    timeout.tv_usec = 0;

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout, sizeof timeout);
}

static void cleanup_timeouts(int fd, time_t now)
{
    struct ipx_client *c, *p;

    c = client_head.prev;

    while (c != &client_head &&
	   (unsigned int)(now - c->last_seen) > opt.timeout) {
	p = c->prev;
	p->next = c->next;
	c->next->prev = p;
	free(c);
	c = p;
    }

    if (client_head.next == &client_head)
	disable_timeout(fd);
}

static void bump_timeout(struct ipx_client *c, time_t now)
{
    /* Remove from list */
    c->prev->next = c->next;
    c->next->prev = c->prev;

    /* Update time */
    c->last_seen = now;

    /* Add to head of list */
    c->next = client_head.next;
    c->prev = &client_head;
    client_head.next = c;
    c->next->prev    = c;
}

static struct ipx_client *find_client(const struct sockaddr *from,
				      const struct ipx_addr *src_addr)
{
    struct ipx_client *c;

    /* Note: this disallows further routing of packets.  That's okay. */

    for (c = client_head.next; c != &client_head; c = c->next) {
	if (!memcmp(from, &c->sin, sizeof c->sin) &&
	    !memcmp(src_addr, &c->ipx, sizeof c->ipx)) {
	    return c;
	}
    }

    return NULL;
}

static int send_ipx_packet(int fd, const struct ipx_client *ipx,
			   const void *data, int len)
{
    return sendto(fd, data, len, 0, (const struct sockaddr *)&ipx->sin,
		  sizeof ipx->sin) != len;
}

static int register_client(int fd, const struct ipx_header *hdr,
			   const struct sockaddr *from, time_t now)
{
    struct ipx_client *c;
    struct ipx_header reply;

    if (!is_ipx_null(&hdr->src_addr))
	return -1;

    /*
     * A current DOSBOX registration packet carries no payload.
     */
    if (htons(hdr->length) != sizeof *hdr)
	return -1;

    c = malloc(sizeof *c);
    if (!c)
	return -1;

    memcpy(&c->sin, from, sizeof c->sin);

    c->ipx.network = 0;
    c->ipx.ip_addr = c->sin.sin_addr.s_addr;
    c->ipx.ip_port = c->sin.sin_port;

    /* Update time */
    c->last_seen = now;

    /* Add to head of list */
    c->next = client_head.next;
    c->prev = &client_head;
    client_head.next = c;
    c->next->prev    = c;

    /* Was this the first client? */
    if (c->next == &client_head)
	enable_timeout(fd);

    /* Send an acknowledgement packet */
    reply.checksum     = 0xffff;
    reply.length       = htons(sizeof reply);
    reply.ptype        = 0;
    reply.transcontrol = 0;
    reply.dst_addr     = c->ipx;
    reply.dst_sock     = hdr->src_sock;
    reply.src_addr     = hdr->dst_addr;
    reply.src_sock     = hdr->dst_sock;

    return send_ipx_packet(fd, c, &reply, sizeof reply);
}

static int ipx_relay_server(int fd)
{
    time_t now;
    union {
	struct ipx_header hdr;
	char buf[65536];
    } pkt;
    struct sockaddr from;
    int fromlen;
    int len, hlen;
    struct ipx_client *s, *d;

    now = time(NULL);

    while (1) {
	/* Potentially redundant, but if so very cheap so we don't care */
	cleanup_timeouts(fd, now);

        fromlen = sizeof from;
	len = recvfrom(fd, (void *)pkt.buf, sizeof pkt, 0, &from, &fromlen);
	now = time(NULL);

	if ((size_t)fromlen < sizeof(struct sockaddr_in))
	    continue;	/* WTF? */

	if (len < (int)sizeof(struct ipx_header))
	    continue;

	if (pkt.hdr.checksum != 0xffff)
	    continue;

	hlen = ntohs(pkt.hdr.length);
	if (hlen < 30 || hlen > len)
	    continue;

	/* No routers, it's all network zero */
	if (pkt.hdr.dst_addr.network | pkt.hdr.src_addr.network)
	    continue;

	/* Reject routed packets */
	if (pkt.hdr.transcontrol)
	    continue;

	if (is_ipx_null(&pkt.hdr.dst_addr)) {
	    /* Sent to the null address: registration packet */
	    register_client(fd, &pkt.hdr, &from, now);
	    continue;
	}

	s = find_client(&from, &pkt.hdr.src_addr);
	if (!s)
	    continue;

	bump_timeout(s, now);
	
	/* Handle timeouts here rather than sending to a dead client */
	cleanup_timeouts(fd, now);
	  
	/* Now s->next is a linked list of all *other* clients */
	
	if (is_ipx_bcst(&pkt.hdr.dst_addr)) {
	    /* Broadcast packet */
	    
	    for (d = s->next; d != &client_head; d = d->next)
		send_ipx_packet(fd, d, pkt.buf, hlen);
	} else {
	    /* Send to a single client */
	    
	    for (d = s->next; d != &client_head; d = d->next) {
		if (!memcmp(&d->ipx, &pkt.hdr.dst_addr,
			    sizeof pkt.hdr.dst_addr)) {
		    send_ipx_packet(fd, d, pkt.buf, hlen);
		    break;
		}
	    }
	}
    }

    return -1;
}	


static int set_sock_addr(const char *host, union sock_addr *s, char **name)
{
    struct addrinfo *addrResult;
    struct addrinfo hints;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = s->sa.sa_family;
    hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    err = getaddrinfo(host, NULL, &hints, &addrResult);
    if (err)
        return err;
    if (addrResult == NULL)
        return EAI_NONAME;
    memcpy(s, addrResult->ai_addr, addrResult->ai_addrlen);
    if (name) {
        if (addrResult->ai_canonname)
            *name = strdup(addrResult->ai_canonname);
        else
            *name = strdup(host);
    }
    freeaddrinfo(addrResult);
    return 0;
}

/*
 * Basic stuff for a daemon to do.  Is there any equivalent for Windows?
 */
static void daemonize_and_write_pidfile(void)
{
#ifndef __WIN32__
  FILE *pidfile = NULL;

  if (opt.pidfile)
      pidfile = fopen(opt.pidfile, "w");
  
  if (!opt.foreground)
      daemon(0, 0);

  if (pidfile) {
      fprintf(pidfile, "%lu\n", (unsigned long)getpid());
      fclose(pidfile);
  }
#endif
}

int main(int argc, char *argv[])
{
    int c;
    char *ep;
    int fd = -1;

    _progname = argv[0];

    while ((c = getopt_long(argc, argv, short_options, long_options, NULL))
	   != -1) {
	switch (c) {
	case 'h':
	    usage();
	    exit(0);
	case 'V':
	    printf("%s: version %s\n", _progname, VERSION_STRING);
	    exit(0);
	case 'f':
	    fd = strtoul(optarg, &ep, 10);
	    if (*ep) {
		usage();
		exit(EX_USAGE);
	    }
	    break;
	case 'p':
	    opt.port = strtoul(optarg, &ep, 10);
	    if (*ep || opt.port > 65535) {
		usage();
		exit(EX_USAGE);
	    }
	    break;
	case 'a':
	    opt.address = optarg;
	    break;
	case 't':
	    opt.timeout = strtoul(optarg, &ep, 10);
	    if (*ep) {
		usage();
		exit(EX_USAGE);
	    }
	    break;
	case 'F':
	    opt.foreground = true;
	    break;
	case 'P':
	    opt.pidfile = optarg;
	    break;
	default:
	    usage();
	    exit(EX_USAGE);
	}
    }

    if (optind != argc) {
      usage();
      exit(EX_USAGE);
    }

    if (fd < 0) {
	int err;
	union sock_addr sa;

	/*** XXX: Fix hardcoded IPv4 assumptions here ***/

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
	    perror(_progname);
	    exit(EX_OSERR);
	}

	memset(&sa, 0, sizeof sa);
	sa.sa.sa_family = AF_INET;
	if (opt.address) {
	    err = set_sock_addr(opt.address, &sa, NULL);
	    if (err) {
		fprintf(stderr, "%s: cannot resolve bind address: %s: %s\n",
			_progname, opt.address, gai_strerror(err));
		exit(EX_NOINPUT);
	    }
	} else {
	    sa.sin.sin_addr.s_addr = INADDR_ANY;
	}
	sa.sin.sin_port = htons(opt.port);

	if (bind(fd, &sa.sa, sizeof sa.sin) < 0) {
	    fprintf(stderr, "%s: cannot bind to port: %s\n",
		    _progname, strerror(errno));
	    exit(EX_OSERR);
	}
    }

    daemonize_and_write_pidfile();

    return ipx_relay_server(fd);
}
