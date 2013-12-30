#include "fcgi_header.h"

#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <stdlib.h>

#include "fcgi_defs.h"

#include "phenom/configuration.h"
#include "phenom/job.h"
#include "phenom/log.h"
#include "phenom/sysutil.h"
#include "phenom/printf.h"
#include "phenom/listener.h"
#include "phenom/socket.h"

#define BUF_SIZE 5000
#define FCGI_SERVER "10.48.25.160"
#define FCGI_PORT "8888"
#define MAXDATASIZE 1000

#define N_NameValue 27
fcgi_name_value nvs[N_NameValue] = {
{"SCRIPT_FILENAME", "/home/work/local/httpd/htdocs/ip.php"},
{"SCRIPT_NAME", "/test.php"},
{"DOCUMENT_ROOT", "/home/abhigna/"},
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
{"QUERY_STRING", "way=get"},
{"REQUEST_METHOD", "GET"},
{"REDIRECT_STATUS", "200"},
{"SERVER_PROTOCOL", "HTTP/1.1"},
{"HTTP_HOST", "localhost:9000"},
{"HTTP_CONNECTION", "keep-alive"},
{"HTTP_USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.83 Safari/535.11"},
{"HTTP_ACCEPT", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
{"HTTP_ACCEPT_LANGUAGE", "en-US,en;q=0.8"},
};

static bool enable_ssl = false;

// fcgid connected session will have one of these structs associated with it
struct fcgid_state {
  int num_lines;
  ph_sock_t *remote_sock;
  char *script_name;
  char *get;
};

// We'll track our state instances using our own typed memory.
// Use the debug console to inspect it; this is useful to figure out if
// or where you might be leaking memory
static ph_memtype_t mt_state;

static struct ph_memtype_def mt_state_def = {
  "fcgid", "fcgid_state", sizeof(struct fcgid_state), PH_MEM_FLAGS_ZERO
};

void simple_session_1(int sockfd, void *data)
{
    uint16_t req_id = 1;
    uint16_t len=0;
    int nb, i;
    unsigned char *p, *buf, *rbuf;
    fcgi_header* head;
    fcgi_begin_request* begin_req = create_begin_request(req_id);

    struct fcgid_state *state = data;    

    // nvs[0].value = state->script_name;
    // nvs[18].value = state->get;
    
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

    printf("Total bytes sending %ld\n", p-buf);
    print_bytes(buf, p-buf);

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
        if(nb == 0)
            break;
        fcgi_process_buffer(rbuf, rbuf+(size_t)nb, &rlst, state->remote_sock);

    }

    for(rec=rlst; rec!=NULL; rec=rec->next)
    {
      /*if(rec->header->type == FCGI_STDOUT)*/
      /*printf("PADD<%d>", rec->header->padding_len);*/
      /*printf("%d\n", rec->length);*/
      /*for(i=0;i < rec->length; i++) fprintf(stdout, "%c", ((uchar *)rec->content)[i]);*/
    }
}

static void done_handshake(ph_sock_t *sock, int res)
{
  ph_unused_parameter(sock);
  ph_log(PH_LOG_ERR, "handshake completed with res=%d", res);
}


static void connected(ph_socket_t sockfd, const ph_sockaddr_t *addr,
                      int status, 
                      struct timeval *elapsed, void *arg)
{
  
  if(sockfd != -1 && status ==0) {
    printf("connected successfuly...\n");
  }
  
  if(sockfd == -1) {
    printf("err no\n");
    exit(1);
  }
  
  if(status != 0) {
    printf("status not zero %d\n", status);
    exit(1);
  }

  struct fcgid_state *state = arg;
  
  ph_unused_parameter(elapsed);
  
  simple_session_1((int) sockfd, state);
}

// Called each time the session wakes up.
// The `why` parameter indicates why we were woken up
static void fcgid_processor(ph_sock_t *sock, ph_iomask_t why, void *arg)
{
  struct fcgid_state *state = arg;

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

    state->remote_sock = sock;

    state->script_name = "/home/work/local/httpd/htdocs/ip.php";
    state->get = ph_buf_mem(buf);
    
    struct timeval timeout = { 60, 0 };

    ph_socket_t sockfd;
    ph_sockaddr_t addr;
    struct addrinfo hints, *ai;
  
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(FCGI_SERVER, FCGI_PORT, &hints, &ai)) {
      return PH_ERR;
    }

    ph_sockaddr_set_from_addrinfo(&addr, ai);

    ph_nbio_init(0);
    
    sockfd = ph_socket_for_addr(&addr, SOCK_STREAM, PH_SOCK_CLOEXEC);
    ph_socket_connect(sockfd, &addr, &timeout, connected, state);

    ph_stm_printf(sock->stream, "You said [%d]: ", state->num_lines);
    ph_stm_write(sock->stream, ph_buf_mem(buf), ph_buf_len(buf), NULL);

    // We're done with buf, so we must release it
    ph_buf_delref(buf);
    
    return 0;
  }
}

// Called each time the listener has accepted a client connection
static void acceptor(ph_listener_t *lstn, ph_sock_t *sock)
{
  ph_unused_parameter(lstn);
  // Allocate an fcgid_state instance and stash it.
  // This is set to be zero'd on creation and will show up as the
  // `arg` parameter in `fcgid_processor`
  sock->job.data = ph_mem_alloc(mt_state);
  // Tell it how to dispatch
  sock->callback = fcgid_processor;
  ph_log(PH_LOG_ERR, "accepted `P{sockaddr:%p}", (void*)&sock->peername);
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
  ph_variant_t* conf;
  ph_variant_t* conf_node;

  // Must be called prior to calling any other phenom functions
  ph_library_init();

  while ((c = getopt(argc, argv, "p:l:c:4s")) != -1) {
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
      case 'c':
        // ph_config_load_config_file(optarg);
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
  
  // conf = ph_config_get_global();
  /* conf_node = ph_var_jsonpath_get(conf, "$.SERVER.PORT"); */
  /* printf("\t%d", conf_node->type); */
  
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
  ph_config_load_config_file("/home/work/git/fcgi-client/conf.json");

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

  lstn = ph_listener_new("fcgid-server", acceptor);
  ph_listener_bind(lstn, &addr);
  ph_listener_enable(lstn, true);

  // Run
  ph_sched_run();

  return 0;
}

/* vim:ts=2:sw=2:et:
 */
