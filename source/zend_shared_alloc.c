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
   | Authors: Andi Gutmans <andi@php.net>                                 |
   |          Zeev Suraski <zeev@php.net>                                 |
   |          Stanislav Malyshev <stas@zend.com>                          |
   |          Dmitry Stogov <dmitry@php.net>                              |
   +----------------------------------------------------------------------+
*/

#if defined(__linux__) && defined(HAVE_MEMFD_CREATE)
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
# include <sys/mman.h>
#endif

#include <errno.h>
#include "zend_shared_alloc.h"
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <fcntl.h>
#ifndef ZEND_WIN32
# include <sys/types.h>
# include <signal.h>
# include <sys/stat.h>
# include <stdio.h>
#endif

#ifdef HAVE_MPROTECT
# include "sys/mman.h"
#endif

#define SEM_FILENAME_PREFIX ".ZendSem."
#define S_H(s) g_shared_alloc_handler->s

/* True globals */
/* old/new mapping. We can use true global even for ZTS because its usage
   is wrapped with exclusive lock anyway */
static const zend_shared_memory_handlers* g_shared_alloc_handler = NULL;
static const char* g_shared_model;
/* pointer to globals allocated in SHM and shared across processes */
zend_smm_shared_globals* smm_shared_globals;

#ifndef ZEND_WIN32
#ifdef ZTS
static MUTEX_T zts_lock;
#endif
int lock_file = -1;
static char lockfile_name[MAXPATHLEN];
#endif

#pragma region zend_alloc_win32_handlers

#ifdef ZEND_WIN32

#include "php.h"
#include "zend_execute.h"
#include "zend_system_id.h"

#define ACCEL_FILEMAP_NAME "ZendOPcache.SharedMemoryArea"
#define ACCEL_MUTEX_NAME "ZendOPcache.SharedMemoryMutex"
#define ACCEL_EVENT_SOURCE "Zend OPcache"


/* address of mapping base and address of execute_ex */
#define ACCEL_BASE_POINTER_SIZE (2 * sizeof(void*))

static HANDLE memfile = NULL, memory_mutex = NULL;
static void* mapping_base;

#define MAX_MAP_RETRIES 25


static char* create_name_with_username(char* name)
{
	static char newname[MAXPATHLEN + 1 + 32 + 1 + 20 + 1 + 32 + 1];
	char* p = newname;
	p += strlcpy(newname, name, MAXPATHLEN + 1);
	*(p++) = '@';
	memcpy(p, accel_uname_id, 32);
	p += 32;
	*(p++) = '@';
	p += strlcpy(p, "embed", 21);
	*(p++) = '@';
	memcpy(p, zend_system_id, 32);
	p += 32;
	*(p++) = '\0';
	ZEND_ASSERT(p - newname <= sizeof(newname));

	return newname;
}

void zend_shared_alloc_create_lock(void)
{
	memory_mutex = CreateMutex(NULL, FALSE, create_name_with_username(ACCEL_MUTEX_NAME));
	if (!memory_mutex) {
		zend_accel_error(ACCEL_LOG_FATAL, "Cannot create mutex (error %u)", GetLastError());
		return;
	}
	ReleaseMutex(memory_mutex);
}

void zend_shared_alloc_lock_win32(void)
{
	DWORD waitRes = WaitForSingleObject(memory_mutex, INFINITE);

	if (waitRes == WAIT_FAILED) {
		zend_accel_error(ACCEL_LOG_ERROR, "Cannot lock mutex");
	}
}

void zend_shared_alloc_unlock_win32(void)
{
	ReleaseMutex(memory_mutex);
}


static void zend_win_error_message(int type, char* msg, int err)
{
	HANDLE h;
	char* ev_msgs[2];
	char* buf = php_win32_error_to_msg(err);

	h = RegisterEventSource(NULL, TEXT(ACCEL_EVENT_SOURCE));
	ev_msgs[0] = msg;
	ev_msgs[1] = buf;
	ReportEvent(h,				  // event log handle
		EVENTLOG_ERROR_TYPE,  // event type
		0,                    // category zero
		err,				  // event identifier
		NULL,                 // no user security identifier
		2,                    // one substitution string
		0,                    // no data
		ev_msgs,              // pointer to string array
		NULL);                // pointer to data
	DeregisterEventSource(h);

	zend_accel_error(type, "%s", msg);

	php_win32_error_msg_free(buf);
}

static int zend_shared_alloc_reattach(size_t requested_size, const char** error_in)
{
	int err;
	void* wanted_mapping_base;
	MEMORY_BASIC_INFORMATION info;
	void* execute_ex_base;
	int execute_ex_moved;

	mapping_base = MapViewOfFileEx(memfile, FILE_MAP_ALL_ACCESS, 0, 0, ACCEL_BASE_POINTER_SIZE, NULL);
	if (mapping_base == NULL) {
		err = GetLastError();
		zend_win_error_message(ACCEL_LOG_FATAL, "Unable to read base address", err);
		*error_in = "read mapping base";
		return ALLOC_FAILURE;
	}
	wanted_mapping_base = ((void**)mapping_base)[0];
	execute_ex_base = ((void**)mapping_base)[1];
	UnmapViewOfFile(mapping_base);

	execute_ex_moved = (void*)execute_ex != execute_ex_base;

	/* Check if execute_ex is at the same address and if the requested address space is free */
	if (execute_ex_moved ||
		VirtualQuery(wanted_mapping_base, &info, sizeof(info)) == 0 ||
		info.State != MEM_FREE ||
		info.RegionSize < requested_size) {

		if (execute_ex_moved) {
			err = ERROR_INVALID_ADDRESS;
			zend_win_error_message(ACCEL_LOG_FATAL, "Opcode handlers are unusable due to ASLR. Please setup opcache.file_cache and opcache.file_cache_fallback directives for more convenient Opcache usage", err);
		}
		else {
			err = ERROR_INVALID_ADDRESS;
			zend_win_error_message(ACCEL_LOG_FATAL, "Base address marks unusable memory region. Please setup opcache.file_cache and opcache.file_cache_fallback directives for more convenient Opcache usage", err);
		}
		return ALLOC_FAILURE;
	}

	mapping_base = MapViewOfFileEx(memfile, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0, wanted_mapping_base);

	if (mapping_base == NULL) {
		err = GetLastError();
		if (err == ERROR_INVALID_ADDRESS) {
			zend_win_error_message(ACCEL_LOG_FATAL, "Unable to reattach to base address", err);
			return ALLOC_FAILURE;
		}
		return ALLOC_FAIL_MAPPING;
	}
	else {
		DWORD old;

		if (!VirtualProtect(mapping_base, requested_size, PAGE_READWRITE, &old)) {
			err = GetLastError();
			zend_win_error_message(ACCEL_LOG_FATAL, "VirtualProtect() failed", err);
			return ALLOC_FAIL_MAPPING;
		}
	}

	smm_shared_globals = (zend_smm_shared_globals*)((char*)mapping_base + ACCEL_BASE_POINTER_SIZE);

	return SUCCESSFULLY_REATTACHED;
}

static int create_segments(size_t requested_size, zend_shared_segment*** shared_segments_p, int* shared_segments_count, const char** error_in)
{
	int err = 0, ret;
	zend_shared_segment* shared_segment;
	int map_retries = 0;
	void* default_mapping_base_set[] = { 0, 0 };
	/* TODO:
	  improve fixed addresses on x64. It still makes no sense to do it as Windows addresses are virtual per se and can or should be randomized anyway
	  through Address Space Layout Radomization (ASLR). We can still let the OS do its job and be sure that each process gets the same address if
	  desired. Not done yet, @zend refused but did not remember the exact reason, pls add info here if one of you know why :)
	*/
#if defined(_WIN64)
	void* vista_mapping_base_set[] = { (void*)0x0000100000000000, (void*)0x0000200000000000, (void*)0x0000300000000000, (void*)0x0000700000000000, 0 };
	DWORD size_high = (requested_size >> 32), size_low = (requested_size & 0xffffffff);
#else
	void* vista_mapping_base_set[] = { (void*)0x20000000, (void*)0x21000000, (void*)0x30000000, (void*)0x31000000, (void*)0x50000000, 0 };
	DWORD size_high = 0, size_low = requested_size;
#endif
	void** wanted_mapping_base = default_mapping_base_set;

	zend_shared_alloc_lock_win32();
	/* Mapping retries: When Apache2 restarts, the parent process startup routine
	   can be called before the child process is killed. In this case, the mapping will fail
	   and we have to sleep some time (until the child releases the mapping object) and retry.*/
	do {
		memfile = OpenFileMapping(FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, create_name_with_username(ACCEL_FILEMAP_NAME));
		if (memfile == NULL) {
			err = GetLastError();
			break;
		}

		ret = zend_shared_alloc_reattach(requested_size, error_in);
		if (ret == ALLOC_FAIL_MAPPING) {
			err = GetLastError();
			/* Mapping failed, wait for mapping object to get freed and retry */
			CloseHandle(memfile);
			memfile = NULL;
			if (++map_retries >= MAX_MAP_RETRIES) {
				break;
			}
			zend_shared_alloc_unlock_win32();
			Sleep(1000 * (map_retries + 1));
			zend_shared_alloc_lock_win32();
		}
		else {
			zend_shared_alloc_unlock_win32();
			return ret;
		}
	} while (1);

	if (map_retries == MAX_MAP_RETRIES) {
		zend_shared_alloc_unlock_win32();
		zend_win_error_message(ACCEL_LOG_FATAL, "Unable to open file mapping", err);
		*error_in = "OpenFileMapping";
		return ALLOC_FAILURE;
	}

	/* creating segment here */
	*shared_segments_count = 1;
	*shared_segments_p = (zend_shared_segment**)calloc(1, sizeof(zend_shared_segment) + sizeof(void*));
	if (!*shared_segments_p) {
		err = GetLastError();
		zend_shared_alloc_unlock_win32();
		zend_win_error_message(ACCEL_LOG_FATAL, "calloc() failed", err);
		*error_in = "calloc";
		return ALLOC_FAILURE;
	}
	shared_segment = (zend_shared_segment*)((char*)(*shared_segments_p) + sizeof(void*));
	(*shared_segments_p)[0] = shared_segment;

	memfile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE | SEC_COMMIT, size_high, size_low,
		create_name_with_username(ACCEL_FILEMAP_NAME));
	if (memfile == NULL) {
		err = GetLastError();
		zend_shared_alloc_unlock_win32();
		zend_win_error_message(ACCEL_LOG_FATAL, "Unable to create file mapping", err);
		*error_in = "CreateFileMapping";
		return ALLOC_FAILURE;
	}

	/* Starting from Windows Vista, heap randomization occurs which might cause our mapping base to
	   be taken (fail to map). So we try to map into one of the hard coded predefined addresses
	   in high memory. */
	if (!ZCG(accel_directives).mmap_base || !*ZCG(accel_directives).mmap_base) {
		wanted_mapping_base = vista_mapping_base_set;
	}
	else {
		char* s = ZCG(accel_directives).mmap_base;

		/* skip leading 0x, %p assumes hexdecimal format anyway */
		if (*s == '0' && *(s + 1) == 'x') {
			s += 2;
		}
		if (sscanf(s, "%p", &default_mapping_base_set[0]) != 1) {
			zend_shared_alloc_unlock_win32();
			zend_win_error_message(ACCEL_LOG_FATAL, "Bad mapping address specified in opcache.mmap_base", err);
			return ALLOC_FAILURE;
		}
	}

	do {
		shared_segment->p = mapping_base = MapViewOfFileEx(memfile, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0, *wanted_mapping_base);
		if (*wanted_mapping_base == NULL) { /* Auto address (NULL) is the last option on the array */
			break;
		}
		wanted_mapping_base++;
	} while (!mapping_base);

	if (mapping_base == NULL) {
		err = GetLastError();
		zend_shared_alloc_unlock_win32();
		zend_win_error_message(ACCEL_LOG_FATAL, "Unable to create view for file mapping", err);
		*error_in = "MapViewOfFile";
		return ALLOC_FAILURE;
	}
	else {
		DWORD old;

		if (!VirtualProtect(mapping_base, requested_size, PAGE_READWRITE, &old)) {
			err = GetLastError();
			zend_win_error_message(ACCEL_LOG_FATAL, "VirtualProtect() failed", err);
			return ALLOC_FAILURE;
		}

		((void**)mapping_base)[0] = mapping_base;
		((void**)mapping_base)[1] = (void*)execute_ex;
	}

	shared_segment->pos = ACCEL_BASE_POINTER_SIZE;
	shared_segment->size = requested_size - ACCEL_BASE_POINTER_SIZE;

	zend_shared_alloc_unlock_win32();

	return ALLOC_SUCCESS;
}

static int detach_segment(zend_shared_segment* shared_segment)
{
	zend_shared_alloc_lock_win32();
	if (mapping_base) {
		UnmapViewOfFile(mapping_base);
		mapping_base = NULL;
	}
	CloseHandle(memfile);
	memfile = NULL;
	zend_shared_alloc_unlock_win32();
	CloseHandle(memory_mutex);
	memory_mutex = NULL;
	return 0;
}

static size_t segment_type_size(void)
{
	return sizeof(zend_shared_segment);
}

const zend_shared_memory_handlers zend_alloc_win32_handlers = {
	create_segments,
	detach_segment,
	segment_type_size
};


#endif

#pragma endregion zend_alloc_win32_handlers

static const zend_shared_memory_handler_entry handler_table[] = {
#ifdef USE_MMAP
	{ "mmap", &zend_alloc_mmap_handlers },
#endif
#ifdef USE_SHM
	{ "shm", &zend_alloc_shm_handlers },
#endif
#ifdef USE_SHM_OPEN
	{ "posix", &zend_alloc_posix_handlers },
#endif
#ifdef ZEND_WIN32
	{ "win32", &zend_alloc_win32_handlers },
#endif
	{ NULL, NULL}
};

#ifndef ZEND_WIN32
void zend_shared_alloc_create_lock(char* lockfile_path)
{
}
#endif

static void no_memory_bailout(size_t allocate_size, const char* error)
{
	zend_accel_error_noreturn(ACCEL_LOG_FATAL, "Unable to allocate shared memory segment of %zu bytes: %s: %s (%d)", allocate_size, error ? error : "unknown", strerror(errno), errno);
}

static void copy_shared_segments(void* to, void* from, int count, int size)
{
	zend_shared_segment** shared_segments_v = (zend_shared_segment**)to;
	void* shared_segments_to_p = ((char*)to + count * (sizeof(void*)));
	void* shared_segments_from_p = from;
	int i;

	for (i = 0; i < count; i++) {
		shared_segments_v[i] = shared_segments_to_p;
		memcpy(shared_segments_to_p, shared_segments_from_p, size);
		shared_segments_to_p = ((char*)shared_segments_to_p + size);
		shared_segments_from_p = ((char*)shared_segments_from_p + size);
	}
}

static int zend_shared_alloc_try(const zend_shared_memory_handler_entry* he, size_t requested_size, zend_shared_segment*** shared_segments_p, int* shared_segments_count, const char** error_in)
{
	int res;
	g_shared_alloc_handler = he->handler;
	g_shared_model = he->name;
	ZSMMG(shared_segments) = NULL;
	ZSMMG(shared_segments_count) = 0;

	res = S_H(create_segments)(requested_size, shared_segments_p, shared_segments_count, error_in);

	if (res) {
		/* this model works! */
		return res;
	}
	if (*shared_segments_p) {
		int i;
		/* cleanup */
		for (i = 0; i < *shared_segments_count; i++) {
			if ((*shared_segments_p)[i]->p && (*shared_segments_p)[i]->p != (void*)-1) {
				S_H(detach_segment)((*shared_segments_p)[i]);
			}
		}
		free(*shared_segments_p);
		*shared_segments_p = NULL;
	}
	g_shared_alloc_handler = NULL;
	return ALLOC_FAILURE;
}

int zend_shared_alloc_startup(size_t requested_size, size_t reserved_size)
{
	zend_shared_segment** tmp_shared_segments;
	size_t shared_segments_array_size;
	zend_smm_shared_globals tmp_shared_globals, * p_tmp_shared_globals;
	const char* error_in = NULL;
	const zend_shared_memory_handler_entry* he;
	int res = ALLOC_FAILURE;
	int i;

	/* shared_free must be valid before we call zend_shared_alloc()
	 * - make it temporarily point to a local variable
	 */
	smm_shared_globals = &tmp_shared_globals;
	ZSMMG(shared_free) = requested_size - reserved_size; /* goes to tmp_shared_globals.shared_free */

#ifndef ZEND_WIN32
	zend_shared_alloc_create_lock(ZCG(accel_directives).lockfile_path);
#else
	zend_shared_alloc_create_lock();
#endif

	if (ZCG(accel_directives).memory_model && ZCG(accel_directives).memory_model[0]) {
		const char* model = ZCG(accel_directives).memory_model;
		/* "cgi" is really "shm"... */
		if (strncmp(ZCG(accel_directives).memory_model, "cgi", sizeof("cgi")) == 0) {
			model = "shm";
		}

		for (he = handler_table; he->name; he++) {
			if (strcmp(model, he->name) == 0) {
				res = zend_shared_alloc_try(he, requested_size, &ZSMMG(shared_segments), &ZSMMG(shared_segments_count), &error_in);
				if (res) {
					/* this model works! */
					break;
				}
			}
		}
	}

	if (res == FAILED_REATTACHED) {
		smm_shared_globals = NULL;
		return res;
	}

	if (!g_shared_alloc_handler) {
		/* try memory handlers in order */
		for (he = handler_table; he->name; he++) {
			res = zend_shared_alloc_try(he, requested_size, &ZSMMG(shared_segments), &ZSMMG(shared_segments_count), &error_in);
			if (res) {
				/* this model works! */
				break;
			}
		}
	}

	if (!g_shared_alloc_handler) {
		no_memory_bailout(requested_size, error_in);
		return ALLOC_FAILURE;
	}

	if (res == SUCCESSFULLY_REATTACHED) {
		return res;
	}

	for (i = 0; i < ZSMMG(shared_segments_count); i++) {
		ZSMMG(shared_segments)[i]->end = ZSMMG(shared_segments)[i]->size;
	}

	shared_segments_array_size = ZSMMG(shared_segments_count) * S_H(segment_type_size)();

	/* move shared_segments and shared_free to shared memory */
	ZCG(locked) = 1; /* no need to perform a real lock at this point */

	p_tmp_shared_globals = (zend_smm_shared_globals*)zend_shared_alloc(sizeof(zend_smm_shared_globals));
	if (!p_tmp_shared_globals) {
		zend_accel_error_noreturn(ACCEL_LOG_FATAL, "Insufficient shared memory!");
		return ALLOC_FAILURE;
	}
	memset(p_tmp_shared_globals, 0, sizeof(zend_smm_shared_globals));

	tmp_shared_segments = zend_shared_alloc(shared_segments_array_size + ZSMMG(shared_segments_count) * sizeof(void*));
	if (!tmp_shared_segments) {
		zend_accel_error_noreturn(ACCEL_LOG_FATAL, "Insufficient shared memory!");
		return ALLOC_FAILURE;
	}

	copy_shared_segments(tmp_shared_segments, ZSMMG(shared_segments)[0], ZSMMG(shared_segments_count), S_H(segment_type_size)());

	*p_tmp_shared_globals = tmp_shared_globals;
	smm_shared_globals = p_tmp_shared_globals;

	free(ZSMMG(shared_segments));
	ZSMMG(shared_segments) = tmp_shared_segments;

	ZSMMG(shared_memory_state).positions = (size_t*)zend_shared_alloc(sizeof(size_t) * ZSMMG(shared_segments_count));
	if (!ZSMMG(shared_memory_state).positions) {
		zend_accel_error_noreturn(ACCEL_LOG_FATAL, "Insufficient shared memory!");
		return ALLOC_FAILURE;
	}

	if (reserved_size) {
		i = ZSMMG(shared_segments_count) - 1;
		if (ZSMMG(shared_segments)[i]->size - ZSMMG(shared_segments)[i]->pos >= reserved_size) {
			ZSMMG(shared_segments)[i]->end = ZSMMG(shared_segments)[i]->size - reserved_size;
			ZSMMG(reserved) = (char*)ZSMMG(shared_segments)[i]->p + ZSMMG(shared_segments)[i]->end;
			ZSMMG(reserved_size) = reserved_size;
		}
		else {
			zend_accel_error_noreturn(ACCEL_LOG_FATAL, "Insufficient shared memory!");
			return ALLOC_FAILURE;
		}
	}

	ZCG(locked) = 0;

	return res;
}

void zend_shared_alloc_shutdown(void)
{
	zend_shared_segment** tmp_shared_segments;
	zend_shared_segment* shared_segments_buf[16];
	size_t shared_segments_array_size;
	zend_smm_shared_globals tmp_shared_globals;
	int i;

	tmp_shared_globals = *smm_shared_globals;
	smm_shared_globals = &tmp_shared_globals;
	shared_segments_array_size = ZSMMG(shared_segments_count) * (S_H(segment_type_size)() + sizeof(void*));
	if (shared_segments_array_size > 16) {
		tmp_shared_segments = malloc(shared_segments_array_size);
	}
	else {
		tmp_shared_segments = shared_segments_buf;
	}
	copy_shared_segments(tmp_shared_segments, ZSMMG(shared_segments)[0], ZSMMG(shared_segments_count), S_H(segment_type_size)());
	ZSMMG(shared_segments) = tmp_shared_segments;

	for (i = 0; i < ZSMMG(shared_segments_count); i++) {
		S_H(detach_segment)(ZSMMG(shared_segments)[i]);
	}
	if (shared_segments_array_size > 16) {
		free(ZSMMG(shared_segments));
	}
	ZSMMG(shared_segments) = NULL;
	g_shared_alloc_handler = NULL;
#ifndef ZEND_WIN32
	close(lock_file);

# ifdef ZTS
	tsrm_mutex_free(zts_lock);
# endif
#endif
}

static size_t zend_shared_alloc_get_largest_free_block(void)
{
	int i;
	size_t largest_block_size = 0;

	for (i = 0; i < ZSMMG(shared_segments_count); i++) {
		size_t block_size = ZSMMG(shared_segments)[i]->end - ZSMMG(shared_segments)[i]->pos;

		if (block_size > largest_block_size) {
			largest_block_size = block_size;
		}
	}
	return largest_block_size;
}

#define MIN_FREE_MEMORY 64*1024

#define SHARED_ALLOC_FAILED() do {		\
		zend_accel_error(ACCEL_LOG_WARNING, "Not enough free shared space to allocate %zu bytes (%zu bytes free)", size, ZSMMG(shared_free)); \
		if (zend_shared_alloc_get_largest_free_block() < MIN_FREE_MEMORY) { \
			ZSMMG(memory_exhausted) = 1; \
		} \
	} while (0)

void* zend_shared_alloc(size_t size)
{
	ZEND_ASSERT(ZCG(locked));

	int i;
	unsigned int block_size = ZEND_ALIGNED_SIZE(size);

	if (UNEXPECTED(block_size < size)) {
		zend_accel_error_noreturn(ACCEL_LOG_ERROR, "Possible integer overflow in shared memory allocation (%zu + %zu)", size, PLATFORM_ALIGNMENT);
	}

	if (block_size > ZSMMG(shared_free)) { /* No hope to find a big-enough block */
		SHARED_ALLOC_FAILED();
		return NULL;
	}
	for (i = 0; i < ZSMMG(shared_segments_count); i++) {
		if (ZSMMG(shared_segments)[i]->end - ZSMMG(shared_segments)[i]->pos >= block_size) { /* found a valid block */
			void* retval = (void*)(((char*)ZSMMG(shared_segments)[i]->p) + ZSMMG(shared_segments)[i]->pos);

			ZSMMG(shared_segments)[i]->pos += block_size;
			ZSMMG(shared_free) -= block_size;
			ZEND_ASSERT(((uintptr_t)retval & 0x7) == 0); /* should be 8 byte aligned */
			return retval;
		}
	}
	SHARED_ALLOC_FAILED();
	return NULL;
}

static zend_always_inline zend_ulong zend_rotr3(zend_ulong key)
{
	return (key >> 3) | (key << ((sizeof(key) * 8) - 3));
}

int zend_shared_memdup_size(void* source, size_t size)
{
	void* old_p;
	zend_ulong key = (zend_ulong)source;

	key = zend_rotr3(key);
	if ((old_p = zend_hash_index_find_ptr(&ZCG(xlat_table), key)) != NULL) {
		/* we already duplicated this pointer */
		return 0;
	}
	zend_hash_index_add_new_ptr(&ZCG(xlat_table), key, source);
	return ZEND_ALIGNED_SIZE(size);
}

static zend_always_inline void* _zend_shared_memdup(void* source, size_t size, bool get_xlat, bool set_xlat, bool free_source)
{
	void* old_p, * retval;
	zend_ulong key;

	if (get_xlat) {
		key = (zend_ulong)source;
		key = zend_rotr3(key);
		if ((old_p = zend_hash_index_find_ptr(&ZCG(xlat_table), key)) != NULL) {
			/* we already duplicated this pointer */
			return old_p;
		}
	}
	retval = ZCG(mem);
	ZCG(mem) = (void*)(((char*)ZCG(mem)) + ZEND_ALIGNED_SIZE(size));
	memcpy(retval, source, size);
	if (set_xlat) {
		if (!get_xlat) {
			key = (zend_ulong)source;
			key = zend_rotr3(key);
		}
		zend_hash_index_add_new_ptr(&ZCG(xlat_table), key, retval);
	}
	if (free_source) {
		efree(source);
	}
	return retval;
}

void* zend_shared_memdup_get_put_free(void* source, size_t size)
{
	return _zend_shared_memdup(source, size, true, true, true);
}

void* zend_shared_memdup_put_free(void* source, size_t size)
{
	return _zend_shared_memdup(source, size, false, true, true);
}

void* zend_shared_memdup_free(void* source, size_t size)
{
	return _zend_shared_memdup(source, size, false, false, true);
}

void* zend_shared_memdup_get_put(void* source, size_t size)
{
	return _zend_shared_memdup(source, size, true, true, false);
}

void* zend_shared_memdup_put(void* source, size_t size)
{
	return _zend_shared_memdup(source, size, false, true, false);
}

void* zend_shared_memdup(void* source, size_t size)
{
	return _zend_shared_memdup(source, size, false, false, false);
}

void zend_shared_alloc_safe_unlock(void)
{
	if (ZCG(locked)) {
		zend_shared_alloc_unlock();
	}
}

void zend_shared_alloc_lock(void)
{
	ZEND_ASSERT(!ZCG(locked));

	ZCG(locked) = 1;
}

void zend_shared_alloc_unlock(void)
{
	ZEND_ASSERT(ZCG(locked));

	ZCG(locked) = 0;
}

void zend_shared_alloc_init_xlat_table(void)
{
	/* Prepare translation table */
	zend_hash_init(&ZCG(xlat_table), 128, NULL, NULL, 0);
}

void zend_shared_alloc_destroy_xlat_table(void)
{
	/* Destroy translation table */
	zend_hash_destroy(&ZCG(xlat_table));
}

void zend_shared_alloc_clear_xlat_table(void)
{
	zend_hash_clean(&ZCG(xlat_table));
}

uint32_t zend_shared_alloc_checkpoint_xlat_table(void)
{
	return ZCG(xlat_table).nNumUsed;
}

void zend_shared_alloc_restore_xlat_table(uint32_t checkpoint)
{
	zend_hash_discard(&ZCG(xlat_table), checkpoint);
}

void zend_shared_alloc_register_xlat_entry(const void* key_pointer, const void* value)
{
	zend_ulong key = (zend_ulong)key_pointer;

	key = zend_rotr3(key);
	zend_hash_index_add_new_ptr(&ZCG(xlat_table), key, (void*)value);
}

void* zend_shared_alloc_get_xlat_entry(const void* key_pointer)
{
	void* retval;
	zend_ulong key = (zend_ulong)key_pointer;

	key = zend_rotr3(key);
	if ((retval = zend_hash_index_find_ptr(&ZCG(xlat_table), key)) == NULL) {
		return NULL;
	}
	return retval;
}

size_t zend_shared_alloc_get_free_memory(void)
{
	return ZSMMG(shared_free);
}

void zend_shared_alloc_save_state(void)
{
	int i;

	for (i = 0; i < ZSMMG(shared_segments_count); i++) {
		ZSMMG(shared_memory_state).positions[i] = ZSMMG(shared_segments)[i]->pos;
	}
	ZSMMG(shared_memory_state).shared_free = ZSMMG(shared_free);
}

void zend_shared_alloc_restore_state(void)
{
	int i;

	for (i = 0; i < ZSMMG(shared_segments_count); i++) {
		ZSMMG(shared_segments)[i]->pos = ZSMMG(shared_memory_state).positions[i];
	}
	ZSMMG(shared_free) = ZSMMG(shared_memory_state).shared_free;
	ZSMMG(memory_exhausted) = 0;
	ZSMMG(wasted_shared_memory) = 0;
}

const char* zend_accel_get_shared_model(void)
{
	return g_shared_model;
}

void zend_accel_shared_protect(bool protected)
{
#ifdef HAVE_MPROTECT
	int i;

	if (!smm_shared_globals) {
		return;
	}

	const int mode = protected ? PROT_READ : PROT_READ | PROT_WRITE;

	for (i = 0; i < ZSMMG(shared_segments_count); i++) {
		mprotect(ZSMMG(shared_segments)[i]->p, ZSMMG(shared_segments)[i]->end, mode);
	}
#elif defined(ZEND_WIN32)
	int i;

	if (!smm_shared_globals) {
		return;
	}

	const int mode = protected ? PAGE_READONLY : PAGE_READWRITE;

	for (i = 0; i < ZSMMG(shared_segments_count); i++) {
		DWORD oldProtect;
		if (!VirtualProtect(ZSMMG(shared_segments)[i]->p, ZSMMG(shared_segments)[i]->end, mode, &oldProtect)) {
			zend_accel_error_noreturn(ACCEL_LOG_ERROR, "Failed to protect memory");
		}
	}
#endif
}

bool zend_accel_in_shm(void* ptr)
{
	int i;

	if (!smm_shared_globals) {
		return false;
	}

	for (i = 0; i < ZSMMG(shared_segments_count); i++) {
		if ((char*)ptr >= (char*)ZSMMG(shared_segments)[i]->p &&
			(char*)ptr < (char*)ZSMMG(shared_segments)[i]->p + ZSMMG(shared_segments)[i]->end) {
			return true;
		}
	}
	return false;
}
