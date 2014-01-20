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

#ifndef FCGI_HEADER_H
#define FCGI_HEADER_H

// Because phenom/defs.h defined _BSD_SOURCE and _GNU_SOURCE 
// even if they have been define !
// To fix compiler warnings we have to put "phenom/socket.h"
// first...
#include "phenom/socket.h"

#include "fcgi_defs.h"

#include <stdint.h>
#include <stdlib.h>

/* Bytes from LSB to MSB 0..3 */
#define BYTE_0(x) ((x) & 0xff)
#define BYTE_1(x) ((x)>>8 & 0xff)
#define BYTE_2(x) ((x)>>16 & 0xff)
#define BYTE_3(x) ((x)>>24 & 0xff)

typedef unsigned char uchar;
typedef enum{
    fcgi_state_version = 0,
    fcgi_state_type,
    fcgi_state_request_id_hi,
    fcgi_state_request_id_lo,
    fcgi_state_content_len_hi,
    fcgi_state_content_len_lo,
    fcgi_state_padding_len,
    fcgi_state_reserved,
    fcgi_state_content_begin,
    fcgi_state_content_proc,
    fcgi_state_padding,
    fcgi_state_done
} fcgi_state;

typedef struct fcgi_record_{
    fcgi_header* header;
    void *content;
    size_t offset, length;
    fcgi_state state;
    struct fcgi_record_* next;
} fcgi_record;

typedef fcgi_record fcgi_record_list;
fcgi_record* fcgi_record_create();

#define FCGI_PROCESS_AGAIN 1
#define FCGI_PROCESS_DONE 2
#define FCGI_PROCESS_ERR 3

fcgi_header* create_header(unsigned char type,uint16_t request_id);
fcgi_begin_request* create_begin_request(uint16_t request_id);
void serialize(uchar* buffer, void *st, size_t size);

uint32_t serialize_name_value(uchar* buffer, fcgi_name_value* nv);
void print_bytes(uchar *buf, int n);

#define PRINT_OPAQUE_STRUCT(p)  print_mem((p), sizeof(*(p)))
void print_mem(void const *vp, size_t n);

void fcgi_process_buffer(uchar *beg_buf,uchar *end_buf, fcgi_record_list** head, ph_sock_t* sock);


#endif
