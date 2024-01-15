/*
   +----------------------------------------------------------------------+
   | Zend OPcache                                                         |
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | https://www.php.net/license/3_01.txt                                 |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Dmitry Stogov <dmitry@php.net>                              |
   +----------------------------------------------------------------------+
*/

#ifndef ZEND_FILE_CACHE_H
#define ZEND_FILE_CACHE_H

#include "Optimizer/zend_optimizer.h"

#define ACCEL_LOG_FATAL					0
#define ACCEL_LOG_ERROR					1
#define ACCEL_LOG_WARNING				2
#define ACCEL_LOG_INFO					3
#define ACCEL_LOG_DEBUG					4


#ifdef PHP_WIN32
#define S_IRUSR S_IREAD
#define S_IWUSR S_IWRITE
#define S_IXUSR S_IEXEC
#define S_IRGRP S_IREAD
#define S_IWGRP S_IWRITE
#define S_IXGRP S_IEXEC
#define S_IROTH S_IREAD
#define S_IWOTH S_IWRITE
#define S_IXOTH S_IEXEC

#undef getgid
#define getgroups(a, b) 0
#define getgid() 1
#define getuid() 1
#endif

#define ZEND_AUTOGLOBAL_MASK_SERVER  (1 << 0)
#define ZEND_AUTOGLOBAL_MASK_ENV     (1 << 1)
#define ZEND_AUTOGLOBAL_MASK_REQUEST (1 << 2)

#define ADLER32_INIT 1     /* initial Adler-32 value */

#pragma region phpw

/*** file locking ***/
#ifndef ZEND_WIN32
extern int lock_file;
#endif

#if defined(ZEND_WIN32)
# define ENABLE_FILE_CACHE_FALLBACK 0
#else
# define ENABLE_FILE_CACHE_FALLBACK 0
#endif

#if ZEND_WIN32
typedef unsigned __int64 accel_time_t;
#else
typedef time_t accel_time_t;
#endif


typedef struct _zend_accel_directives {
	zend_long           memory_consumption;
	zend_long           max_accelerated_files;
	double         max_wasted_percentage;
	char* user_blacklist_filename;
	zend_long           force_restart_timeout;
	bool      use_cwd;
	bool      ignore_dups;
	bool      validate_timestamps;
	bool      revalidate_path;
	bool      save_comments;
	bool      record_warnings;
	bool      protect_memory;
	bool      file_override_enabled;
	bool      enable_cli;
	bool      validate_permission;
#ifndef ZEND_WIN32
	bool      validate_root;
#endif
	zend_ulong     revalidate_freq;
	zend_ulong     file_update_protection;
	char* error_log;
#ifdef ZEND_WIN32
	char* mmap_base;
#endif
	char* memory_model;
	zend_long           log_verbosity_level;

	zend_long           optimization_level;
	zend_long           opt_debug_level;
	zend_long           max_file_size;
	zend_long           interned_strings_buffer;
	char* restrict_api;
#ifndef ZEND_WIN32
	char* lockfile_path;
#endif
	char* file_cache;
	bool      file_cache_only;
	bool      file_cache_consistency_checks;
#if ENABLE_FILE_CACHE_FALLBACK
	bool      file_cache_fallback;
#endif
#ifdef HAVE_HUGE_CODE_PAGES
	bool      huge_code_pages;
#endif
	char* preload;
#ifndef ZEND_WIN32
	char* preload_user;
#endif
#ifdef ZEND_WIN32
	char* cache_id;
#endif
} zend_accel_directives;

typedef struct _zend_early_binding {
	zend_string* lcname;
	zend_string* rtd_key;
	zend_string* lc_parent_name;
	uint32_t cache_slot;
} zend_early_binding;

typedef struct _zend_persistent_script {
	zend_script    script;
	zend_long      compiler_halt_offset;   /* position of __HALT_COMPILER or -1 */
	int            ping_auto_globals_mask; /* which autoglobals are used by the script */
	accel_time_t   timestamp;              /* the script modification time */
	bool      corrupted;
	bool      is_phar;
	bool      empty;
	uint32_t       num_warnings;
	uint32_t       num_early_bindings;
	zend_error_info** warnings;
	zend_early_binding* early_bindings;

	void* mem;                    /* shared memory area used by script structures */
	size_t         size;                   /* size of used shared memory */

	struct zend_persistent_script_dynamic_members {
		time_t       last_used;
		zend_ulong   hits;
		unsigned int memory_consumption;
		time_t       revalidate;
	} dynamic_members;
} zend_persistent_script;

typedef struct _zend_accel_globals {
	bool               counted;   /* the process uses shared memory */
	bool               enabled;
	bool               locked;    /* thread obtained exclusive lock */
	bool               accelerator_enabled; /* accelerator enabled for current request */
	bool               pcre_reseted;
	zend_accel_directives   accel_directives;
	zend_string* cwd;                  /* current working directory or NULL */
	zend_string* include_path;         /* current value of "include_path" directive */
	char                    include_path_key[32]; /* key of current "include_path" */
	char                    cwd_key[32];          /* key of current working directory */
	int                     include_path_key_len;
	bool                    include_path_check;
	int                     cwd_key_len;
	bool                    cwd_check;
	int                     auto_globals_mask;
	time_t                  request_time;
	time_t                  last_restart_time; /* used to synchronize SHM and in-process caches */
	HashTable               xlat_table;
#ifndef ZEND_WIN32
	zend_ulong              root_hash;
#endif
	/* preallocated shared-memory block to save current script */
	void* mem;
	zend_persistent_script* current_persistent_script;
	/* cache to save hash lookup on the same INCLUDE opcode */
	const zend_op* cache_opline;
	zend_persistent_script* cache_persistent_script;
	/* preallocated buffer for keys */
	zend_string             key;
	char                    _key[MAXPATHLEN * 8];
} zend_accel_globals;

/* memory write protection */
#define SHM_PROTECT() \
	do { \
		if (ZCG(accel_directives).protect_memory) { \
			zend_accel_shared_protect(true); \
		} \
	} while (0)

#define SHM_UNPROTECT() \
	do { \
		if (ZCG(accel_directives).protect_memory) { \
			zend_accel_shared_protect(false); \
		} \
	} while (0)

#define ZCSG(element)   (element)
#define IS_ACCEL_INTERNED(str) false

#ifdef ZTS
# define ZCG(v)	ZEND_TSRMG(accel_globals_id, zend_accel_globals *, v)
extern int accel_globals_id;
# ifdef COMPILE_DL_OPCACHE
ZEND_TSRMLS_CACHE_EXTERN()
# endif
#else
# define ZCG(v) (accel_globals.v)
extern zend_accel_globals accel_globals;
#endif

extern bool file_cache_only;
extern char accel_uname_id[32];

#pragma endregion accel_globals

int zend_file_cache_script_store(zend_persistent_script* script, bool in_shm);
zend_persistent_script* zend_file_cache_script_load(zend_file_handle* file_handle);
void zend_file_cache_invalidate(zend_string* full_path);

zend_string* ZEND_FASTCALL accel_new_interned_string(zend_string* str);

void zend_accel_error(int type, const char* format, ...);

zend_op_array* persistent_compile_file(zend_file_handle* file_handle, int type);
int persistent_startup(char* cache_id, char* file_cache);

#endif /* ZEND_FILE_CACHE_H */
