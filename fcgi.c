#include "fcgi_defs.h"
#include "fcgi_header.h"

#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include "phenom/defs.h"
#include "phenom/configuration.h"
#include "phenom/job.h"
#include "phenom/log.h"
#include "phenom/sysutil.h"
#include "phenom/printf.h"
#include "phenom/listener.h"
#include "phenom/socket.h"
#include <sysexits.h>
#include <stdlib.h>

#define BUF_SIZE 5000
#define FCGI_SERVER "10.48.25.160"
#define FCGI_PORT "9000"
#define MAXDATASIZE 1000

#define N_NameValue 27
fcgi_name_value nvs[N_NameValue] = {
{"SCRIPT_FILENAME", "/home/abhigna/test.php"},
{"SCRIPT_NAME", "/test.php"},
{"DOCUMENT_ROOT", "/home/work/"},
{"REQUEST_URI", "/test.php"},
{"PHP_SELF", "/test.php"},
{"TERM", "linux"},
{"PATH", ""},
{"PHP_FCGI_CHILDREN", "2"},
{"PHP_FCGI_MAX_REQUESTS", "1000"},
{"FCGI_ROLE", "RESPONDER"},
{"SERVER_SOFTWARE", "lighttpd/1.4.29"},
{"SERVER_NAME", "SimpleServer"},
{"GATEWAY_INTERFACE", "CGI/1.1"},
{"SERVER_PORT", FCGI_PORT},
{"SERVER_ADDR", FCGI_SERVER},
{"REMOTE_PORT", ""},
{"REMOTE_ADDR", "127.0.0.1"},
{"PATH_INFO", "no value"},
{"QUERY_STRING", "no value"},
{"REQUEST_METHOD", "GET"},
{"REDIRECT_STATUS", "200"},
{"SERVER_PROTOCOL", "HTTP/1.1"},
{"HTTP_HOST", "localhost:9000"},
{"HTTP_CONNECTION", "keep-alive"},
{"HTTP_USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.83 Safari/535.11"},
{"HTTP_ACCEPT", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
{"HTTP_ACCEPT_LANGUAGE", "en-US,en;q=0.8"},
};

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int fcgi_connect(int *sock){
    int sockfd;//, numbytes;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(FCGI_SERVER, FCGI_PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    freeaddrinfo(servinfo);
    *sock = sockfd;
    return 0;
}


void simple_session_1(int sockfd, ph_sock_t *sock)
{
    uint16_t req_id = 1;
    uint16_t len=0;
    int nb, i;
    unsigned char *p, *buf, *rbuf;
    fcgi_header* head;
    fcgi_begin_request* begin_req = create_begin_request(req_id);

    rbuf = malloc(BUF_SIZE);
    buf  = malloc(BUF_SIZE);
    p = buf;
    serialize(p, begin_req->header, sizeof(fcgi_header));
    p += sizeof(fcgi_header);
    serialize(p, begin_req->body, sizeof(fcgi_begin_request_body));
    p += sizeof(fcgi_begin_request_body);

    /* Sending fcgi_params */
    head = create_header(FCGI_PARAMS, req_id);

    len = 0;
    /* print_bytes(buf, p-buf); */
    for(i = 0; i< N_NameValue; i++) {
        nb = serialize_name_value(p, &nvs[i]);
        len += nb;
    }

    head->content_len_lo = BYTE_0(len);
    head->content_len_hi = BYTE_1(len);


    serialize(p, head, sizeof(fcgi_header));
    p += sizeof(fcgi_header);

    for(i = 0; i< N_NameValue; i++) {
        nb = serialize_name_value(p, &nvs[i]);
        p += nb;
    }

    head->content_len_lo = 0;
    head->content_len_hi = 0;

    serialize(p, head, sizeof(fcgi_header));
    p += sizeof(fcgi_header);

    /*printf("Total bytes sending %ld", p-buf);*/

    /*print_bytes(buf, p-buf);*/

    if (send(sockfd, buf, p-buf, 0) == -1) {
      perror("send");
      close(sockfd);
      return;
    }
    
    fcgi_record_list *rlst = NULL, *rec;
     
    while(1) {
        if ((nb = recv(sockfd, rbuf, BUF_SIZE-1, 0)) == -1) {
            perror("recv");
            exit(1);
        }
        if(nb == 0) break;
        
        fcgi_process_buffer(rbuf, rbuf+(size_t)nb, &rlst, sock);
    }
    
    for(rec=rlst; rec!=NULL; rec=rec->next)
    {
      // if(rec->header->type == FCGI_STDOUT) {
      // printf("PADD<%d>", rec->header->padding_len);
      // }
      // printf("%d\n", rec->length);
      // for(i=0;i < rec->length; i++) {
      // fprintf(stdout, "%c", ((uchar *)rec->content)[i]);
      // }
    }
}

static bool enable_ssl = false;

// Each connected session will have one of these structs associated with it.
// We don't really do anything useful with it here, it's just to show how
// to associate data with a session
struct echo_state {
  int num_lines;
};

// We'll track our state instances using our own typed memory.
// Use the debug console to inspect it; this is useful to figure out if
// or where you might be leaking memory
static ph_memtype_t mt_state;
static struct ph_memtype_def mt_state_def = {
  "example", "echo_state", sizeof(struct echo_state), PH_MEM_FLAGS_ZERO
};

// Called each time the session wakes up.
// The `why` parameter indicates why we were woken up
static void echo_processor(ph_sock_t *sock, ph_iomask_t why, void *arg)
{
  struct echo_state *state = arg;
  ph_buf_t *buf;

  // If the socket encountered an error, or if the timeout was reached
  // (there's a default timeout, even if we didn't override it), then
  // we tear down the session
  if (why & (PH_IOMASK_ERR|PH_IOMASK_TIME)) {
    ph_log(PH_LOG_ERR, "disconnecting `P{sockaddr:%p}", (void*)&sock->peername);
    ph_sock_shutdown(sock, PH_SOCK_SHUT_RDWR);
    ph_mem_free(mt_state, state);
    ph_sock_free(sock);
    return;
  }

  // We loop because echo_processor is only triggered by newly arriving
  // data or events from the kernel.  If we have data buffered and only
  // partially consume it, we won't get woken up until the next data
  // arrives, if ever.
  while (1) {
    // Try to read a line of text.
    // This returns a slice over the underlying buffer (if the line was
    // smaller than a buffer) or a freshly made contiguous buffer (if the
    // line was larger than our buffer segment size).  Either way, we
    // own a reference to the returned buffer and should treat it as
    // a read-only slice.
    buf = ph_sock_read_line(sock);
    if (!buf) {
      // Not available yet, we'll try again later
      return;
    }

    // We got a line; update our state
    state->num_lines++;

    // Send our response.  The data is buffered and automatically sent
    // to the client as it becomes writable, so we don't need to handle
    // partial writes or EAGAIN here.

    // If this was a "real" server, we would still check the return value
    // from the writes and proceed to tear down the session if things failed.

    // Note that buf includes the trailing CRLF, so our response
    // will implicitly end with CRLF too.

    int sockfd;
    fcgi_record *h;
    nvs[0].value = "/home/work/local/httpd/htdocs/ip.php";
    nvs[18].value = ph_buf_mem(buf);
    
    fcgi_connect(&sockfd);
    
    simple_session_1(sockfd, sock);
    
    ph_stm_printf(sock->stream, "You said [%d]: ", state->num_lines);
    ph_stm_write(sock->stream, ph_buf_mem(buf), ph_buf_len(buf), NULL);

    
    close(sockfd);
    
    return 0;
    

    // We're done with buf, so we must release it
    ph_buf_delref(buf);
  }
}

static void done_handshake(ph_sock_t *sock, int res)
{
  ph_unused_parameter(sock);
  ph_log(PH_LOG_ERR, "handshake completed with res=%d", res);
}

// Called each time the listener has accepted a client connection
static void acceptor(ph_listener_t *lstn, ph_sock_t *sock)
{
  ph_unused_parameter(lstn);

  // Allocate an echo_state instance and stash it.
  // This is set to be zero'd on creation and will show up as the
  // `arg` parameter in `echo_processor`
  sock->job.data = ph_mem_alloc(mt_state);

  // Tell it how to dispatch
  sock->callback = echo_processor;

  ph_log(PH_LOG_ERR, "accepted `P{sockaddr:%p}", (void*)&sock->peername);

  if (enable_ssl) {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    SSL *ssl;

    SSL_CTX_set_cipher_list(ctx, "ALL");
    SSL_CTX_use_RSAPrivateKey_file(ctx, "examples/server.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_certificate_file(ctx, "examples/server.pem", SSL_FILETYPE_PEM);
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    ssl = SSL_new(ctx);

    ph_sock_openssl_enable(sock, ssl, false, done_handshake);
  }

  ph_sock_enable(sock, true);
}

int main(int argc, char **argv)
{
  int c;
  uint16_t portno = 8080;
  char *addrstring = NULL;
  ph_sockaddr_t addr;
  ph_listener_t *lstn;
  bool use_v4 = false;

  // Must be called prior to calling any other phenom functions
  ph_library_init();

  while ((c = getopt(argc, argv, "p:l:4s")) != -1) {
    switch (c) {
      case '4':
        use_v4 = true;
        break;
      case 's':
        enable_ssl = true;
        break;
      case 'l':
        addrstring = optarg;
        break;
      case 'p':
        portno = atoi(optarg);
        break;
      default:
        ph_fdprintf(STDERR_FILENO,
            "Invalid parameters\n"
            " -4          - interpret address as an IPv4 address\n"
            " -l ADDRESS  - which address to listen on\n"
            " -p PORTNO   - which port to listen on\n"
            " -s          - enable SSL\n"
        );
        exit(EX_USAGE);
    }
  }

  if (enable_ssl) {
    ph_library_init_openssl();
  }

  // Set up the address that we're going to listen on
  if ((use_v4 && ph_sockaddr_set_v4(&addr, addrstring, portno) != PH_OK) ||
      (!use_v4 && ph_sockaddr_set_v6(&addr, addrstring, portno) != PH_OK)) {
    ph_fdprintf(STDERR_FILENO,
        "Invalid address [%s]:%d",
        addrstring ? addrstring : "*",
        portno
    );
    exit(EX_USAGE);
  }

  // Register our memtype
  mt_state = ph_memtype_register(&mt_state_def);

  // Optional config file for tuning internals
  ph_config_load_config_file("/path/to/my/config.json");

  // Enable the non-blocking IO manager
  ph_nbio_init(0);

  ph_log(PH_LOG_ERR, "will listen on `P{sockaddr:%p}", (void*)&addr);

  // This enables a very simple request/response console
  // that allows you to run diagnostic commands:
  // `echo memory | nc -UC /tmp/phenom-debug-console`
  // (on BSD systems, use `nc -Uc`!)
  // The code behind this is in
  // https://github.com/facebook/libphenom/blob/master/corelib/debug_console.c
  ph_debug_console_start("/tmp/phenom-debug-console");

  lstn = ph_listener_new("echo-server", acceptor);
  ph_listener_bind(lstn, &addr);
  ph_listener_enable(lstn, true);

  // Run
  ph_sched_run();

  return 0;
}

/* vim:ts=2:sw=2:et:
 */
