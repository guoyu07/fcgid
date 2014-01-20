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

#ifndef FCGI_DEFS_H
#define FCGI_DEFS_H

#define FCGI_LISTENSOCK_FILENO 0
#define FCGI_VERSION_1         1

#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

#define FCGI_NULL_REQUEST_ID     0

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char request_id_hi;
    unsigned char request_id_lo;
    unsigned char content_len_hi;
    unsigned char content_len_lo;
    unsigned char padding_len;
    unsigned char reserved;
} fcgi_header;

/* Generic structure for both name and value
 * Does not contain the length values since
 */
typedef struct {
    char *name, *value;
} fcgi_name_value;

/* Management records */
typedef struct {
    unsigned char type;    
    unsigned char reserved[7];
} fcgi_unknown_type_body;

typedef struct {
    fcgi_header header;
    fcgi_unknown_type_body body;
} fcgi_unknown_type;

/* Variable names for FCGI_GET_VALUES / FCGI_GET_VALUES_RESULT */
#define FCGI_MAX_CONNS  "FCGI_MAX_CONNS"
#define FCGI_MAX_REQS   "FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS "FCGI_MPXS_CONNS"

/* Application records */

/* Mask for flags in fcgi_begin_request_body */
#define FCGI_KEEP_CONN  1
/*
 * Values for role component of fcgi_begin_request
 */
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

typedef struct {
    unsigned char  role_hi;
    unsigned char  role_lo;
    unsigned char  flags;
    unsigned char  reserved[5];
} fcgi_begin_request_body;

typedef struct {
    fcgi_header *header;
    fcgi_begin_request_body *body;
} fcgi_begin_request;


typedef struct {
    unsigned char app_status;
    unsigned char appStatusB2;
    unsigned char appStatusB1;
    unsigned char appStatusB0;
    unsigned char protocol_status;
    unsigned char reserved[3];
} fcgi_end_request_body;

typedef struct {
    fcgi_header header;
    fcgi_end_request_body body;
} fcgi_end_request;

/*
 * Values for protocolStatus component of FCGI_EndRequestBody
 */
#define FCGI_REQUEST_COMPLETE 0
#define FCGI_CANT_MPX_CONN    1
#define FCGI_OVERLOADED       2
#define FCGI_UNKNOWN_ROLE     3

#endif
