#include "pch.h"
#include "types.h"
#include "file.h"
#include "mylibc.h"

char* create_temp_filename(const char* basename, kernel32_functions_t* kernel32)
{
	DWORD tick_count;
	int result = 0;
	int basename_len = 0;
	char* name = (char*)my_malloc(MAX_NAME_LEN);
	if (!name)
		return NULL;
	
	my_memset(name, 0, MAX_NAME_LEN);

	if ((result = GetTempPathA(MAX_PATH, name)) == 0)
	{
		result = -1;
		goto __cleanup;
	}

	my_strncat(name, basename, my_strlen(basename));


	basename_len = my_strlen(name);
	name[basename_len] = '-';

	tick_count = kernel32->GetTickCount();
	
	my_lltoa(tick_count, name + (basename_len + 1), 10);

	return name;

__cleanup:

	my_free(name);
	return NULL;
}


int cleanup_temp_file(const char* filename, kernel32_functions_t* kernel32)
{
	int result = 0;
	if (kernel32->DeleteFileA(filename))
		result = 0;
	else
		result = -1;
	my_free((void*)filename);

	return result;
}
