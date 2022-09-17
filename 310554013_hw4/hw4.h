#pragma once
// #include <vector>
#include <string>
// #include <string.h>
// #include "hw4_elf.h"
using namespace std;

typedef enum
{
    LOADED,
    RUNNING,
    OTHERS
} state_t;

typedef struct breakpoint
{
    int id;
    unsigned long addr;
    string s_addr;
    unsigned long ori_code;
} breakpoint_t;