#ifndef _H_KEYSTORE_REQUEST_H
#define _H_KEYSTORE_REQUEST_H

#include <stdint.h>
#include "keystore_report.h"
#include "keystore_defs.h"

#define REGUSER_REQUEST 0x1
#define REGRULE_REQUEST 0x2
#define RUNTIME_REQUEST 0x3

typedef struct reguser_request {
    int user_len;
    int password_len;
    char username[USERNAME_SIZE];
    char password[PASSWORD_SIZE];
} reguser_request_t;

typedef struct regrule_request {
    uintptr_t rid;
    int num_triggers;
    int num_actions;

    char username[USERNAME_SIZE];
    char password[PASSWORD_SIZE];

    // Support atmost 20 trigger and action services for now
    char key_trigger[MAX_TRIGGERS][ACTION_KEY_SIZE];
    char key_action[MAX_ACTIONS][ACTION_KEY_SIZE];
    char key_rule[RULE_KEY_SIZE];

    // Hash sizes according to the Keystone SDK
    char rule_bin_hash[EAPP_BIN_HASH_SIZE];
    char runtime_bin_hash[RUNTIME_BIN_HASH_SIZE];
} regrule_request_t;


typedef struct runtime_request {
    uintptr_t user_id;
    uintptr_t rule_id;
    struct report_t report;
} runtime_request_t;

typedef struct request {
    char type;
    union {
        runtime_request_t runtime_req;
        regrule_request_t regrule_req;
        reguser_request_t reguser_req;
    } data;
} request_t;

#endif