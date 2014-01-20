
#include "fcgi_header.h"

static bool enable_ssl = false;

extern ph_memtype_t mt_state;
extern struct ph_memtype_def mt_state_def;

void acceptor(ph_listener_t *lstn, ph_sock_t *sock);

int main(int argc, char **argv)
{
  int c;
  uint16_t portno;
  char *addrstring = NULL;
  ph_sockaddr_t addr;
  ph_listener_t *lstn;
  bool use_v4 = true;
  
  ph_string_t *conf_server_host;
  ph_string_t *conf_server_host_name;
  char *hostname;

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
        ph_config_load_config_file(optarg);
        break;
      default:
        ph_fdprintf(STDERR_FILENO,
            "Invalid parameters\n"
            " -4          - interpret address as an IPv4 address\n"
            " -l ADDRESS  - which address to listen on\n"
            " -c CONFIG   - which address to listen on\n"                    
            " -p PORTNO   - which port to listen on\n"
            " -s          - enable SSL\n"
        );
        exit(EX_USAGE);
    }
  }

  // host address
  conf_server_host = ph_config_query_string_cstr("$.SERVER.HOST", NULL);
  addrstring = conf_server_host->buf;

  // hostname
  conf_server_host_name = ph_config_query_string_cstr("$.SERVER.NAME", NULL);
  hostname = conf_server_host_name->buf;

  // port number
  portno = ph_config_query_int("$.SERVER.PORT", 8080);

  // enable ssl?
  enable_ssl = (bool) ph_config_query_int("$.SERVER.ENABLE_SSL", 0);
  
  // printf("%s\n", conf_host->buf);
  // printf("%d-true: %d-false: %d\n", portno, true, false);
  
  if (enable_ssl) {
    ph_log(PH_LOG_ERR, "connection will use SSL");
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

  lstn = ph_listener_new(hostname, acceptor);
  ph_listener_bind(lstn, &addr);
  ph_listener_enable(lstn, true);

  // Run
  ph_sched_run();

  return 0;
}

