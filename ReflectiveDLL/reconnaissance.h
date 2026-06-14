#pragma once

#include "pch.h"
#include "framework.h"
#include "types.h"
#include "rfdll.h"
#include "misc.h"
#include "ldr.h"
#include "syscalls.h"

bool enable_debug_privilege();


int ret_pid_by_proc_name(wchar_t* proc_name);

int select_target_process(bool is_debug_privilege);
