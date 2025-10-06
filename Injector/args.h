#pragma once

typedef struct _i_args {

	char* url;
	char* process;
	bool is_local;

} i_arg_t;

i_arg_t argument_parser(int argc, char* argv[]);
