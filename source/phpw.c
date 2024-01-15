#include <stdlib.h>
#include "sapi/embed/php_embed.h"

#ifndef TEST_WASM_MAIN
#include <emscripten.h>
#else
#include <direct.h>
#include "ext/standard/php_standard.h"
#include "ext/standard/dl_arginfo.h"
#define EMSCRIPTEN_KEEPALIVE
#endif // !TEST_WASM_MAIN


#include "zend_globals_macros.h"
#include "zend_exceptions.h"
#include "zend_closures.h"

#include "zend_file_cache.h"

#pragma region phpw

void phpw_flush()
{
	fprintf(stdout, "\n");
	fprintf(stderr, "\n");
}

char* EMSCRIPTEN_KEEPALIVE phpw_exec(char* code)
{
	// This sets USE_ZEND_ALLOC=0 to avoid nunmap errors
	setenv("USE_ZEND_ALLOC", "0", 1);
	php_embed_init(0, NULL);
	char* retVal = NULL;

	zend_try
	{
	  zval retZv;

	  zend_eval_string(code, &retZv, "php-wasm evaluate expression");

	  convert_to_string(&retZv);

	  retVal = Z_STRVAL(retZv);
	} zend_catch{
	} zend_end_try();

	phpw_flush();
	php_embed_shutdown();

	return retVal;
}

void EMSCRIPTEN_KEEPALIVE phpw_run(char* code)
{
	setenv("USE_ZEND_ALLOC", "0", 1);
	php_embed_init(0, NULL);
	zend_try
	{
	  zend_eval_string(code, NULL, "php-wasm run script");
	  if (EG(exception))
	  {
		zend_exception_error(EG(exception), E_ERROR);
	  }
	} zend_catch{
		/* int exit_status = EG(exit_status); */
	} zend_end_try();

	phpw_flush();
	php_embed_shutdown();
}

int EMBED_SHUTDOWN = 1;

void phpw(char* file)
{
	setenv("USE_ZEND_ALLOC", "0", 1);
	if (EMBED_SHUTDOWN == 0) {
		php_embed_shutdown();
	}

	php_embed_init(0, NULL);
	EMBED_SHUTDOWN = 0;
	zend_first_try{
	  zend_file_handle file_handle;
	  zend_stream_init_filename(&file_handle, file);
	  // file_handle.primary_script = 1;

	  if (php_execute_script(&file_handle) == FAILURE) {
		php_printf("Failed to execute PHP script.\n");
	  }

	  zend_destroy_file_handle(&file_handle);
	} zend_catch{
		/* int exit_status = EG(exit_status); */
	} zend_end_try();

	phpw_flush();
	php_embed_shutdown();
	EMBED_SHUTDOWN = 1;
}

#pragma endregion phpw


#ifndef TEST_WASM_MAIN

int main() {
	return 0;
}

#else

#pragma region php_embed_init

static char* php_embed_read_cookies(void)
{
	return NULL;
}

static int php_embed_deactivate(void)
{
	fflush(stdout);
	return SUCCESS;
}

static inline size_t php_embed_single_write(const char* str, size_t str_length)
{
	size_t ret;

	ret = fwrite(str, 1, MIN(str_length, 16384), stdout);
	return ret;
}

/* SAPIs only have unbuffered write operations. This is because PHP's output
 * buffering feature will handle any buffering of the output and invoke the
 * SAPI unbuffered write operation when it flushes the buffer.
 */
static size_t php_embed_ub_write(const char* str, size_t str_length)
{
	const char* ptr = str;
	size_t remaining = str_length;
	size_t ret;

	while (remaining > 0) {
		ret = php_embed_single_write(ptr, remaining);
		if (!ret) {
			php_handle_aborted_connection();
		}
		ptr += ret;
		remaining -= ret;
	}

	return str_length;
}

static void php_embed_flush(void* server_context)
{
	if (fflush(stdout) == EOF) {
		php_handle_aborted_connection();
	}
}

static void php_embed_send_header(sapi_header_struct* sapi_header, void* server_context)
{
}

/* The SAPI error logger that is called when the 'error_log' INI setting is not
 * set.
 *
 * https://www.php.net/manual/en/errorfunc.configuration.php#ini.error-log
 */
static void php_embed_log_message(const char* message, int syslog_type_int)
{
	fprintf(stderr, "%s\n", message);
}

static void php_embed_register_variables(zval* track_vars_array)
{
	php_import_environment_variables(track_vars_array);
}

/* Module initialization (MINIT) */
static int php_embed_startup(sapi_module_struct* sapi_module)
{
	return php_module_startup(sapi_module, NULL);
}

EMBED_SAPI_API sapi_module_struct php_embed_module = {
	"embed",                       /* name */
	"PHP Embedded Library",        /* pretty name */

	php_embed_startup,             /* startup */
	php_module_shutdown_wrapper,   /* shutdown */

	NULL,                          /* activate */
	php_embed_deactivate,          /* deactivate */

	php_embed_ub_write,            /* unbuffered write */
	php_embed_flush,               /* flush */
	NULL,                          /* get uid */
	NULL,                          /* getenv */

	php_error,                     /* error handler */

	NULL,                          /* header handler */
	NULL,                          /* send headers handler */
	php_embed_send_header,         /* send header handler */

	NULL,                          /* read POST data */
	php_embed_read_cookies,        /* read Cookies */

	php_embed_register_variables,  /* register server variables */
	php_embed_log_message,         /* Log message */
	NULL,                          /* Get request time */
	NULL,                          /* Child terminate */

	STANDARD_SAPI_MODULE_PROPERTIES
};
/* }}} */

const char HARDCODED_INI[] =
"html_errors=0\n"
"register_argc_argv=1\n"
"implicit_flush=1\n"
"output_buffering=0\n"
"max_execution_time=0\n"
"max_input_time=-1\n\0";

static const zend_function_entry additional_functions[] = {
	ZEND_FE(dl, arginfo_dl)
	ZEND_FE_END
};


int setenv(char* name, char* val, int flag) {
	return 0;
}

void php_embed_treat_data(int arg, char* str, zval* destArray) {

}

EMBED_SAPI_API int php_embed_init(int argc, char** argv)
{
	zend_signal_startup();
	sapi_startup(&php_embed_module);
	php_embed_module.treat_data = php_embed_treat_data;

#ifdef PHP_WIN32
	_fmode = _O_BINARY;			/*sets default for file streams to binary */
	setmode(_fileno(stdin), O_BINARY);		/* make the stdio mode be binary */
	setmode(_fileno(stdout), O_BINARY);		/* make the stdio mode be binary */
	setmode(_fileno(stderr), O_BINARY);		/* make the stdio mode be binary */
#endif

	php_embed_module.ini_entries = HARDCODED_INI;

	/* SAPI-provided functions. */
	php_embed_module.additional_functions = additional_functions;

	/* Module initialization (MINIT) */
	if (php_embed_module.startup(&php_embed_module) == FAILURE) {
		return FAILURE;
	}

	/* Do not chdir to the script's directory. This is akin to calling the CGI
	 * SAPI with '-C'.
	 */
	SG(options) |= SAPI_OPTION_NO_CHDIR;

	SG(request_info).argc = argc;
	SG(request_info).argv = argv;

	/* Request initialization (RINIT) */
	if (php_request_startup() == FAILURE) {
		php_module_shutdown();
		return FAILURE;
	}

	SG(headers_sent) = 1;
	SG(request_info).no_headers = 1;
	php_register_variable("PHP_SELF", "-", NULL);

	return SUCCESS;
}

EMBED_SAPI_API void php_embed_shutdown(void)
{
	php_request_shutdown((void*)0);
	php_module_shutdown();
	sapi_shutdown();
}

#pragma endregion php_embed_init


#define ACCELERATOR_PRODUCT_NAME	"Zend OPcache"

int embed_opcache_compile_file(char* name)
{
	int ret = -1;
	zend_file_handle handle;
	zend_op_array* op_array = NULL;
	zend_execute_data* orig_execute_data = NULL;
	uint32_t orig_compiler_options;

	zend_stream_init_filename(&handle, name);

	orig_execute_data = EG(current_execute_data);
	orig_compiler_options = CG(compiler_options);
	CG(compiler_options) |= ZEND_COMPILE_WITHOUT_EXECUTION;

	if (CG(compiler_options) & ZEND_COMPILE_PRELOAD) {
		/* During preloading, a failure in opcache_compile_file() should result in an overall
		 * preloading failure. Otherwise we may include partially compiled files in the preload
		 * state. */
		op_array = persistent_compile_file(&handle, ZEND_INCLUDE);
	}
	else {
		zend_try{
			op_array = persistent_compile_file(&handle, ZEND_INCLUDE);
		} zend_catch{
			EG(current_execute_data) = orig_execute_data;
			zend_error(E_WARNING, ACCELERATOR_PRODUCT_NAME " could not compile file %s", ZSTR_VAL(handle.filename));
		} zend_end_try();
	}

	CG(compiler_options) = orig_compiler_options;

	if (op_array != NULL) {
		destroy_op_array(op_array);
		efree(op_array);
		ret = 1;
	}
	else {
		ret = 0;
	}
	zend_destroy_file_handle(&handle);
	return ret;
}

int main(int argc, char** argv) {
	char* cwd = _getcwd(NULL, 0);

	php_win32_init_gettimeofday();
	php_win32_ioutil_init();

	php_embed_init(argc, argv);

	if (argc == 1 || (argc == 2 && strcmp(argv[1], "--phpinfo") == 0) || (argc == 3 && strcmp(argv[1], "--exec") == 0)) {

		char* code = "echo phpinfo();";
		if (argc == 3 && strcmp(argv[1], "--exec") == 0) {
			code = argv[2];
		}

		zend_try
		{
		  zend_eval_string(code, NULL, "php-wasm run script");
		  if (EG(exception))
		  {
			zend_exception_error(EG(exception), E_ERROR);
		  }
		} zend_catch{
			/* int exit_status = EG(exit_status); */
		} zend_end_try();
	}
	else if (argc == 3 && strcmp(argv[1], "--opcache-file") == 0) {
		persistent_startup("embed", cwd);
		embed_opcache_compile_file(argv[2]);
	}
	else if (argc == 3 && strcmp(argv[1], "--run") == 0) {
		zend_first_try{
			zend_file_handle file_handle;
			zend_stream_init_filename(&file_handle, argv[2]);
			// file_handle.primary_script = 1;

			if (php_execute_script(&file_handle) == FAILURE) {
				php_printf("Failed to execute PHP script.\n");
			}

			zend_destroy_file_handle(&file_handle);
		} zend_catch{
			/* int exit_status = EG(exit_status); */
		} zend_end_try();
	}

	fprintf(stdout, "\n");
	fprintf(stderr, "\n");
	php_embed_shutdown();
	free(cwd);

	system("pause");
	return 0;
}

#endif

