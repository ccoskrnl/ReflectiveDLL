#pragma once

typedef enum {

	url = 0,
	filename = 1,

} dll_path_type;

typedef struct _i_args {

	dll_path_type dll_src;

	char* filename;
	char* url;
	char* process;
	bool is_local;

} i_arg_t;

i_arg_t argument_parser(int argc, char* argv[]);
