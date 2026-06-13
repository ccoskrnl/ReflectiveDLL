#include "pch.h"
#include "types.h"
#include "file.h"
#include "misc.h"

char* create_temp_filename(const char* basename, kernel32_functions_t* kernel32)
{
	DWORD tick_count;
	int result = 0;
	int basename_len = 0;
	char* name = (char*)custom_malloc(MAX_NAME_LEN);
	if (!name)
		return NULL;
	
	custom_memset(name, 0, MAX_NAME_LEN);

	if ((result = GetTempPathA(MAX_PATH, name)) == 0)
	{
		result = -1;
		goto __cleanup;
	}

	custom_strncat(name, basename, custom_strlen(basename));


	basename_len = custom_strlen(name);
	name[basename_len] = '-';

	tick_count = kernel32->GetTickCount();
	
	custom_lltoa(tick_count, name + (basename_len + 1), 10);

	return name;

__cleanup:

	custom_free(name);
	return NULL;
}


int cleanup_temp_file(const char* filename, kernel32_functions_t* kernel32)
{
	int result = 0;
	if (kernel32->DeleteFileA(filename))
		result = 0;
	else
		result = -1;
	custom_free((void*)filename);

	return result;
}
