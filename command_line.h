#ifndef _H_COMMAND_LINE_H_
#define _H_COMMAND_LINE_H_
#include <stdio.h>
#include "keystore_request.h"

typedef enum {
    REQ_REGUSER,
    REQ_REGRULE,
    REQ_UPDATE_RULE,
    REQ_DELETE_RULE,
} request_type_t;

struct option {
    request_type_t req_type;
    int invalid;
    request_t request;
};
#endif