/*
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "fcgi.h"

#include <stdlib.h>

#define BUF_SIZE 5000

#define MAXDATASIZE 1000

fcgi_name_value nvs[] = {
{"SCRIPT_FILENAME", ""},
{"SCRIPT_NAME", ""},
{"DOCUMENT_ROOT", ""},
{"REQUEST_URI", ""},
{"PHP_SELF", ""},
{"TERM", "linux"},
{"PATH", ""},
{"PHP_FCGI_CHILDREN", "2"},
{"PHP_FCGI_MAX_REQUESTS", "1000"},
{"FCGI_ROLE", "RESPONDER"},
{"SERVER_SOFTWARE", "lighttpd/1.4.29"},
{"SERVER_NAME", "SimpleServer"},
{"GATEWAY_INTERFACE", "CGI/1.1"},
{"SERVER_PORT", ""},
{"SERVER_ADDR", ""},
{"REMOTE_PORT", ""},
{"REMOTE_ADDR", ""},
{"PATH_INFO", "no value"},
{"QUERY_STRING", ""},
{"REQUEST_METHOD", "POST"},
{"REDIRECT_STATUS", "200"},
{"SERVER_PROTOCOL", "HTTP/1.1"},
{"HTTP_HOST", "localhost:9000"},
{"CONTENT_LENGTH", ""},
{"HTTP_CONNECTION", "keep-alive"},
{"HTTP_USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.83 Safari/535.11"},
{"HTTP_ACCEPT", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
{"HTTP_ACCEPT_LANGUAGE", "en-US,en;q=0.8"},
{"CONTENT_TYPE", "application/x-www-form-urlencoded"},
};

#define N_NameValue (sizeof(nvs) / sizeof(fcgi_name_value))

// fcgid connected session will have one of these structs associated with it
struct fcgid_state {
  ph_sock_t *remote_sock;

  int   fcgi_req_id;
  char *remote_addr;
  char *remote_port;

  ph_string_t *server_addr;
  ph_string_t *server_port;
  
  ph_string_t *document_root;
  ph_string_t *request_uri;
  ph_string_t *script_name;
  ph_string_t *post;
};

// We'll track our state instances using our own typed memory.
// Use the debug console to inspect it; this is useful to figure out if
// or where you might be leaking memory
ph_memtype_t mt_state;

struct ph_memtype_def mt_state_def = {
  "fcgid", "fcgid_state", sizeof(struct fcgid_state), PH_MEM_FLAGS_ZERO
};

static inline uint16_t get_num_size(uint16_t i)
{
    uint16_t n = 0;
    do {
        i /= 10;
        n++;
    } while (i > 0);
    return n;
}

char *str_query_string(char *s)
{
  char *p = strchr(s, '?');
  if(p) {
    return strdup(p+1);
  }
  return NULL;
}

char *str_basename(char *s)
{
  char *p = strrchr(s, '/');
  char *q;
  if (p) {
     q = strdup(p+1);
     return q;
   }
  return NULL;
}

char *str_ip_port(char *s)
{
  char *p = strchr(s, ':');
  if(p) {
    return strdup(p+1);
  }
  return NULL;
}

char *str_ip_addr(char *s)
{
  char *path = strdup(s);
  char *p = strchr(s, ']');
  if(p) {
    strncpy(path, s+1, p-s-1);
    path[p-s-1] = '\0';
    return path;
  }
  return s;
}

char *str_request_path(char *s)
{
  char *path = strdup(s);
  char *p = strchr(s, '?');
  if(p) {
    strncpy(path, s, p-s-1);
    path[p-s] = '\0';
    return path;
  }
  return s;
}

/* void name_value(ph_ht_t *ptr_ht, void *data, bool is_post = false) */
/* { */
/*   ph_memtype_t name_value_hash_mem; */
/*   ph_memtype_t str_hd_mem; */
/*   struct fcgid_state *state = data; */

/*   ph_string_make_empty(str_hd_mem, ph_string_len(state->document_root) + ph_string_len(state->request)); */
  
/*   ph_ht_init(&ptr_ht, 1, &ph_ht_string_key_def, &ph_ht_string_val_def); */

/*   ph_string_t *key = ph_string_make_cstr(name_value_hash_mem, "SCRIPT_FILENAME"); */
/*   ph_string_t *val = ph_string_make_cstr(name_value_hash_mem, "val"); */
/*   ph_ht_set(ptr_ht, &key, &val); */
/*   ph_string_delref(key); */
/*   ph_string_delref(val); */
    
/* } */

void simple_session(int sockfd, void *data)
{
    uint16_t req_id;
    uint16_t len = 0;
    int nb, i;
    unsigned char *p, *buf, *rbuf, *content_length;
    fcgi_header* head;
    fcgi_header* post_head;
    
    fcgi_begin_request* begin_req = create_begin_request(req_id);

    struct fcgid_state *state = data;    

    char *post = state->post->buf;

    len = strlen(post);
    content_length = malloc(get_num_size(len));
    sprintf(content_length, "%d", len);

    req_id = state->fcgi_req_id;

    PH_STRING_DECLARE_STACK(script_filename, 128);
    ph_string_printf(&script_filename, "%s", state->document_root->buf);
    if(*(state->script_name->buf) == '/') {
      ph_string_append_cstr(&script_filename, state->script_name->buf + 1);
    } else {
      ph_string_append_cstr(&script_filename, state->script_name->buf);
    }
    ph_string_append_buf(&script_filename, "\0", 1);
    
    printf("request uri: %s\n", state->request_uri->buf);
    printf("script name: %s\n", state->script_name->buf);
    printf("script filename: %s\n", script_filename.buf);
    printf("php self name: %s\n", str_basename(script_filename.buf));
        
    nvs[0].value = script_filename.buf;
    nvs[1].value = state->script_name->buf;
    nvs[2].value = state->document_root->buf;
    nvs[3].value = state->request_uri->buf;
    nvs[4].value = str_basename(state->script_name->buf);

    nvs[13].value = state->server_port->buf;
    nvs[14].value = state->server_addr->buf;
    
    nvs[15].value = state->remote_port;
    nvs[16].value = state->remote_addr;
    
    nvs[18].value = str_query_string(state->request_uri->buf);
    nvs[23].value = content_length;

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

    len = strlen(post);
    post_head = create_header(FCGI_STDIN, req_id);
    post_head->content_len_lo = BYTE_0(len);
    post_head->content_len_hi = BYTE_1(len);

    serialize(p, post_head, sizeof(fcgi_header));
    p += sizeof(fcgi_header);
    serialize(p, post, len);
    p += len;

    post_head->content_len_lo = 0;
    post_head->content_len_hi = 0;

    serialize(p, post_head, sizeof(fcgi_header));
    p += sizeof(fcgi_header);    

    printf("Total bytes sending %ld\n", p-buf);
    print_bytes(buf, p-buf);

    // ph_ht_t ht;
    // Declare a map from ph_string_t* -> ph_string_t*

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
        fcgi_process_buffer(rbuf, rbuf+(size_t)nb, &rlst, state->remote_sock);
    }

    close(sockfd);
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
  
  if(sockfd != -1 && status == 0) {
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
  simple_session((int) sockfd, state);
}

// Called each time the session wakes up.
// The `why` parameter indicates why we were woken up
static void fcgid_processor(ph_sock_t *sock, ph_iomask_t why, void *arg)
{
  struct fcgid_state *state = arg;
  struct timeval timeout = { 60, 0 };

  char *raw_data = NULL;
  ph_variant_t *data;

  ph_variant_t *request_uri_var;
  ph_variant_t *post_var;
  ph_variant_t *script_name_var;
  
  ph_string_t *request_uri_string;
  ph_string_t *post_string;
  ph_string_t *script_name_string;
  
  ph_var_err_t err;
  ph_buf_t *buf;

  ph_buf_t *sub_buf;
  
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

  state->remote_sock = sock;
  state->document_root = ph_config_query_string_cstr("$.DOCUMENT_ROOT", NULL);
  
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
    
    // buf = ph_sock_read_record(sock, "\r\n\r\n", 4);
    
    if (!buf) {
      // Not available yet, we'll try again later
      return;
    }

    sub_buf = ph_buf_new(ph_buf_len(buf)-1);
    // minus 2: \r\n
    ph_buf_copy(buf, sub_buf, 0, ph_buf_len(buf)-2, 0);
    // set last with \0
    ph_buf_set(sub_buf, '\0', ph_buf_len(buf)-2, 1);
      
    if(state->fcgi_req_id > 1000) {
      state->fcgi_req_id = 0;
    } else {
      state->fcgi_req_id++;
    }

    raw_data = ph_buf_mem(sub_buf);
    
    printf("raw data: %s\n", raw_data);
    
    data = ph_json_load_cstr(raw_data, PH_JSON_DECODE_ANY, &err);

    /* if(!data) { */
    /*   ph_log(PH_LOG_ERR, "json decode error: %s", err.text); */
    /*   return; */
    /* } */

    request_uri_var = ph_var_object_get_cstr(data, "request_uri");
    request_uri_string = ph_var_string_val(request_uri_var);
    ph_string_append_buf(request_uri_string, "\0", 1);
    ph_string_addref(request_uri_string);    
    state->request_uri = request_uri_string;
    
    post_var = ph_var_object_get_cstr(data, "post");
    post_string = ph_var_string_val(post_var);
    ph_string_append_buf(post_string, "\0", 1);
    ph_string_addref(post_string);
    state->post = post_string;

    script_name_var = ph_var_object_get_cstr(data, "script_name");
    script_name_string = ph_var_string_val(script_name_var);
    ph_string_append_buf(script_name_string, "\0", 1);
    ph_string_addref(script_name_string);
    state->script_name = script_name_string;

    printf("request uri: %s, post_string: %s, script_name: %s\n", request_uri_string->buf, post_string->buf, script_name_string->buf);
    
    PH_STRING_DECLARE_STACK(remote_addr, 128);
    ph_sockaddr_print(&sock->peername, &remote_addr, true);
    ph_string_append_buf(&remote_addr, "\0", 1);

    state->remote_addr = str_ip_addr(remote_addr.buf);
    state->remote_port = str_ip_port(remote_addr.buf);
    
    printf("IP is: %s, Port is %s \n", str_ip_addr(remote_addr.buf), str_ip_port(remote_addr.buf));
    
    // Send our response.  The data is buffered and automatically sent
    // to the client as it becomes writable, so we don't need to handle
    // partial writes or EAGAIN here.

    // If this was a "real" server, we would still check the return value
    // from the writes and proceed to tear down the session if things failed.

    // Note that buf includes the trailing CRLF, so our response
    // will implicitly end with CRLF too.


    state->server_port = ph_config_query_string_cstr("$.FCGI_SERVER[0].PORT", NULL);
    state->server_addr = ph_config_query_string_cstr("$.FCGI_SERVER[0].HOST", NULL);

    printf("server addr: %s, server port %s\n", state->server_addr->buf, state->server_port->buf);
    
    ph_socket_t sockfd;
    ph_sockaddr_t addr;
    struct addrinfo hints, *ai;
  
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(state->server_addr->buf, state->server_port->buf, &hints, &ai)) {
      return;
    }

    ph_sockaddr_set_from_addrinfo(&addr, ai);

    ph_nbio_init(0);
    
    sockfd = ph_socket_for_addr(&addr, SOCK_STREAM, PH_SOCK_CLOEXEC);
    ph_socket_connect(sockfd, &addr, &timeout, connected, state);

    // We're done with buf, so we must release it
    ph_buf_delref(buf);
    ph_buf_delref(sub_buf);
    ph_var_delref(data);
    ph_string_delref(request_uri_string);
    ph_string_delref(post_string);
    ph_string_delref(script_name_string);
    
    raw_data = NULL;

    return;
  }
}

// Called each time the listener has accepted a client connection
void acceptor(ph_listener_t *lstn, ph_sock_t *sock)
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

