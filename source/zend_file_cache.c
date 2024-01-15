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

#include "zend.h"
#include "zend_virtual_cwd.h"
#include "zend_compile.h"
#include "zend_vm.h"
#include "zend_interfaces.h"
#include "zend_attributes.h"
#include "zend_system_id.h"
#include "zend_enum.h"
#include "zend_observer.h"
#include "zend_inheritance.h"

#include "php.h"

#include "zend_file_cache.h"
#include "zend_shared_alloc.h"
#include "zend_persist.h"

#include "ext/standard/md5.h"
#include "ext/hash/php_hash.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef ZEND_WIN32
typedef int uid_t;
typedef int gid_t;
#include <io.h>
#include <lmcons.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif

#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif

#if __has_feature(memory_sanitizer)
# include <sanitizer/msan_interface.h>
#endif

#ifndef ZTS
zend_accel_globals accel_globals;
#else
int accel_globals_id;
#if defined(COMPILE_DL_OPCACHE)
ZEND_TSRMLS_CACHE_DEFINE()
#endif
#endif

/* true globals, no need for thread safety */
#ifdef ZEND_WIN32
char accel_uname_id[32];
#endif
bool accel_startup_ok = false;
static const char* zps_failure_reason = NULL;
const char* zps_api_failure_reason = NULL;
bool file_cache_only = true;  /* process uses file cache only */
#if ENABLE_FILE_CACHE_FALLBACK
bool fallback_process = false; /* process uses file cache fallback */
#endif

#ifndef O_BINARY
#  define O_BINARY 0
#endif

#define SUFFIX ".bin"


typedef struct _zend_file_cache_metainfo {
	char         magic[8];
	char         system_id[32];
	size_t       mem_size;
	size_t       str_size;
	size_t       script_offset;
	accel_time_t timestamp;
	uint32_t     checksum;
} zend_file_cache_metainfo;

#pragma region zend_accel_error

static void zend_accel_error_va_args(int type, const char* format, va_list args)
{
	time_t timestamp;
	char* time_string;
	FILE* fLog = NULL;

	if (type <= ZCG(accel_directives).log_verbosity_level) {

		timestamp = time(NULL);
		time_string = asctime(localtime(&timestamp));
		time_string[24] = 0;

		if (!ZCG(accel_directives).error_log ||
			!*ZCG(accel_directives).error_log ||
			strcmp(ZCG(accel_directives).error_log, "stderr") == 0) {

			fLog = stderr;
		}
		else {
			fLog = fopen(ZCG(accel_directives).error_log, "a");
			if (!fLog) {
				fLog = stderr;
			}
		}

#ifdef ZTS
		fprintf(fLog, "%s (" ZEND_ULONG_FMT "): ", time_string, (zend_ulong)tsrm_thread_id());
#else
		fprintf(fLog, "%s (%d): ", time_string, getpid());
#endif

		switch (type) {
		case ACCEL_LOG_FATAL:
			fprintf(fLog, "Fatal Error ");
			break;
		case ACCEL_LOG_ERROR:
			fprintf(fLog, "Error ");
			break;
		case ACCEL_LOG_WARNING:
			fprintf(fLog, "Warning ");
			break;
		case ACCEL_LOG_INFO:
			fprintf(fLog, "Message ");
			break;
		case ACCEL_LOG_DEBUG:
			fprintf(fLog, "Debug ");
			break;
		}

		vfprintf(fLog, format, args);
		fprintf(fLog, "\n");

		fflush(fLog);
		if (fLog != stderr) {
			fclose(fLog);
		}
	}
	/* perform error handling even without logging the error */
	switch (type) {
	case ACCEL_LOG_ERROR:
		zend_bailout();
		break;
	case ACCEL_LOG_FATAL:
		exit(-2);
		break;
	}

}

void zend_accel_error(int type, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	zend_accel_error_va_args(type, format, args);
	va_end(args);
}

ZEND_NORETURN void zend_accel_error_noreturn(int type, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	ZEND_ASSERT(type == ACCEL_LOG_FATAL || type == ACCEL_LOG_ERROR);
	zend_accel_error_va_args(type, format, args);
	va_end(args);
	/* Should never reach this. */
	abort();
}

static void replay_warnings(uint32_t num_warnings, zend_error_info** warnings) {
	for (uint32_t i = 0; i < num_warnings; i++) {
		zend_error_info* warning = warnings[i];
		zend_error_zstr_at(warning->type, warning->filename, warning->lineno, warning->message);
	}
}

zend_string* ZEND_FASTCALL accel_new_interned_string(zend_string* str)
{
	return str;
}

#pragma endregion zend_accel_error

#pragma region is_phar_file

static zend_always_inline bool is_phar_file(zend_string* filename)
{
	return filename && ZSTR_LEN(filename) >= sizeof(".phar") &&
		!memcmp(ZSTR_VAL(filename) + ZSTR_LEN(filename) - (sizeof(".phar") - 1), ".phar", sizeof(".phar") - 1) &&
		!strstr(ZSTR_VAL(filename), "://");
}

static inline bool is_cacheable_stream_path(const char* filename)
{
	return memcmp(filename, "file://", sizeof("file://") - 1) == 0 ||
		memcmp(filename, "phar://", sizeof("phar://") - 1) == 0;
}

static int zend_get_stream_timestamp(const char* filename, zend_stat_t* statbuf)
{
	php_stream_wrapper* wrapper;
	php_stream_statbuf stream_statbuf;
	int ret, er;

	if (!filename) {
		return FAILURE;
	}

	wrapper = php_stream_locate_url_wrapper(filename, NULL, STREAM_LOCATE_WRAPPERS_ONLY);
	if (!wrapper) {
		return FAILURE;
	}
	if (!wrapper->wops || !wrapper->wops->url_stat) {
		statbuf->st_mtime = 1;
		return SUCCESS; /* anything other than 0 is considered to be a valid timestamp */
	}

	er = EG(error_reporting);
	EG(error_reporting) = 0;
	zend_try{
		ret = wrapper->wops->url_stat(wrapper, (char*)filename, PHP_STREAM_URL_STAT_QUIET, &stream_statbuf, NULL);
	} zend_catch{
		ret = -1;
	} zend_end_try();
	EG(error_reporting) = er;

	if (ret != 0) {
		return FAILURE;
	}

	*statbuf = stream_statbuf.sb;
	return SUCCESS;
}

#if ZEND_WIN32
static accel_time_t zend_get_file_handle_timestamp_win(zend_file_handle* file_handle, size_t* size)
{
	static unsigned __int64 utc_base = 0;
	static FILETIME utc_base_ft;
	WIN32_FILE_ATTRIBUTE_DATA fdata;

	if (!file_handle->opened_path) {
		return 0;
	}

	if (!utc_base) {
		SYSTEMTIME st;

		st.wYear = 1970;
		st.wMonth = 1;
		st.wDay = 1;
		st.wHour = 0;
		st.wMinute = 0;
		st.wSecond = 0;
		st.wMilliseconds = 0;

		SystemTimeToFileTime(&st, &utc_base_ft);
		utc_base = (((unsigned __int64)utc_base_ft.dwHighDateTime) << 32) + utc_base_ft.dwLowDateTime;
	}

	if (file_handle->opened_path && GetFileAttributesEx(file_handle->opened_path->val, GetFileExInfoStandard, &fdata) != 0) {
		unsigned __int64 ftime;

		if (CompareFileTime(&fdata.ftLastWriteTime, &utc_base_ft) < 0) {
			return 0;
		}

		ftime = (((unsigned __int64)fdata.ftLastWriteTime.dwHighDateTime) << 32) + fdata.ftLastWriteTime.dwLowDateTime - utc_base;
		ftime /= 10000000L;

		if (size) {
			*size = (size_t)((((unsigned __int64)fdata.nFileSizeHigh) << 32) + (unsigned __int64)fdata.nFileSizeLow);
		}
		return (accel_time_t)ftime;
	}
	return 0;
}
#endif

accel_time_t zend_get_file_handle_timestamp(zend_file_handle* file_handle, size_t* size)
{
	zend_stat_t statbuf = { 0 };
#ifdef ZEND_WIN32
	accel_time_t res;
#endif

#ifdef ZEND_WIN32
	res = zend_get_file_handle_timestamp_win(file_handle, size);
	if (res) {
		return res;
	}
#endif

	switch (file_handle->type) {
	case ZEND_HANDLE_FP:
		if (zend_fstat(fileno(file_handle->handle.fp), &statbuf) == -1) {
			if (zend_get_stream_timestamp(ZSTR_VAL(file_handle->filename), &statbuf) != SUCCESS) {
				return 0;
			}
		}
		break;
	case ZEND_HANDLE_FILENAME:
		if (file_handle->opened_path) {
			char* file_path = ZSTR_VAL(file_handle->opened_path);

			if (php_is_stream_path(file_path)) {
				if (zend_get_stream_timestamp(file_path, &statbuf) == SUCCESS) {
					break;
				}
			}
			if (VCWD_STAT(file_path, &statbuf) != -1) {
				break;
			}
		}

		if (zend_get_stream_timestamp(ZSTR_VAL(file_handle->filename), &statbuf) != SUCCESS) {
			return 0;
		}
		break;
	case ZEND_HANDLE_STREAM:
	{
		php_stream* stream = (php_stream*)file_handle->handle.stream.handle;
		php_stream_statbuf sb;
		int ret, er;

		if (!stream ||
			!stream->ops ||
			!stream->ops->stat) {
			return 0;
		}

		er = EG(error_reporting);
		EG(error_reporting) = 0;
		zend_try{
			ret = stream->ops->stat(stream, &sb);
		} zend_catch{
			ret = -1;
		} zend_end_try();
		EG(error_reporting) = er;
		if (ret != 0) {
			return 0;
		}

		statbuf = sb.sb;
	}
	break;

	default:
		return 0;
	}

	if (size) {
		*size = statbuf.st_size;
	}
	return statbuf.st_mtime;
}

#pragma endregion is_phar_file

#pragma region zend_adler32

#define ADLER32_BASE 65521 /* largest prime smaller than 65536 */
#define ADLER32_NMAX 5552
/* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */

#define ADLER32_SCALAR_DO1(buf)        {s1 += *(buf); s2 += s1;}
#define ADLER32_SCALAR_DO2(buf, i)     ADLER32_SCALAR_DO1(buf + i); ADLER32_SCALAR_DO1(buf + i + 1);
#define ADLER32_SCALAR_DO4(buf, i)     ADLER32_SCALAR_DO2(buf, i); ADLER32_SCALAR_DO2(buf, i + 2);
#define ADLER32_SCALAR_DO8(buf, i)     ADLER32_SCALAR_DO4(buf, i); ADLER32_SCALAR_DO4(buf, i + 4);
#define ADLER32_SCALAR_DO16(buf)       ADLER32_SCALAR_DO8(buf, 0); ADLER32_SCALAR_DO8(buf, 8);

static zend_always_inline void adler32_do16_loop(unsigned char* buf, unsigned char* end, unsigned int* s1_out, unsigned int* s2_out)
{
	unsigned int s1 = *s1_out;
	unsigned int s2 = *s2_out;

#ifdef __SSE2__
	const __m128i zero = _mm_setzero_si128();

	__m128i accumulate_s2 = zero;
	unsigned int accumulate_s1 = 0;

	do {
		__m128i read = _mm_loadu_si128((__m128i*) buf); /* [A:P] */

		/* Split the 8-bit-element vector into two 16-bit-element vectors where each element gets zero-extended from 8-bits to 16-bits */
		__m128i lower = _mm_unpacklo_epi8(read, zero);									/* [A:H] zero-extended to 16-bits */
		__m128i higher = _mm_unpackhi_epi8(read, zero);									/* [I:P] zero-extended to 16-bits */
		lower = _mm_madd_epi16(lower, _mm_set_epi16(9, 10, 11, 12, 13, 14, 15, 16));	/* [A * 16:H * 9] */
		higher = _mm_madd_epi16(higher, _mm_set_epi16(1, 2, 3, 4, 5, 6, 7, 8)); 		/* [I * 8:P * 1] */

		/* We'll cheat here: it's difficult to add 16-bit elementwise, but we can do 32-bit additions.
			* The highest value the sum of two elements of the vectors can take is 0xff * 16 + 0xff * 8 < 0xffff.
			* That means there is no carry possible from 16->17 bits so the 32-bit addition is safe. */
		__m128i sum = _mm_add_epi32(lower, higher); /* [A * 16 + I * 8:H * 9 + P * 1] */
		accumulate_s2 = _mm_add_epi32(accumulate_s2, sum);
		accumulate_s1 += s1;

		/* Computes 8-bit element-wise abs(buf - zero) and then sums the elements into two 16 bit parts */
		sum = _mm_sad_epu8(read, zero);
		s1 += _mm_cvtsi128_si32(sum) + _mm_extract_epi16(sum, 4);

		buf += 16;
	} while (buf != end);

	/* For convenience, let's do a rename of variables and let accumulate_s2 = [X, Y, Z, W] */
	__m128i shuffled = _mm_shuffle_epi32(accumulate_s2, _MM_SHUFFLE(1, 0, 0, 2));	/* [Y, X, X, Z] */
	accumulate_s2 = _mm_add_epi32(accumulate_s2, shuffled);							/* [X + Y, Y + X, Z + X, W + Z] */
	shuffled = _mm_shuffle_epi32(accumulate_s2, _MM_SHUFFLE(3, 3, 3, 3));			/* [X + Y, X + Y, X + Y, X + Y] */
	accumulate_s2 = _mm_add_epi32(accumulate_s2, shuffled);							/* [/, /, /, W + Z + X + Y] */
	s2 += accumulate_s1 * 16 + _mm_cvtsi128_si32(accumulate_s2);
#else
	do {
		ADLER32_SCALAR_DO16(buf);
		buf += 16;
	} while (buf != end);
#endif

	* s1_out = s1;
	*s2_out = s2;
}

unsigned int zend_adler32(unsigned int checksum, unsigned char* buf, uint32_t len)
{
	unsigned int s1 = checksum & 0xffff;
	unsigned int s2 = (checksum >> 16) & 0xffff;
	unsigned char* end;

	while (len >= ADLER32_NMAX) {
		len -= ADLER32_NMAX;
		end = buf + ADLER32_NMAX;
		adler32_do16_loop(buf, end, &s1, &s2);
		buf = end;
		s1 %= ADLER32_BASE;
		s2 %= ADLER32_BASE;
	}

	if (len) {
		if (len >= 16) {
			end = buf + (len & 0xfff0);
			len &= 0xf;
			adler32_do16_loop(buf, end, &s1, &s2);
			buf = end;
		}
		if (len) {
			end = buf + len;
			do {
				ADLER32_SCALAR_DO1(buf);
				buf++;
			} while (buf != end);
		}
		s1 %= ADLER32_BASE;
		s2 %= ADLER32_BASE;
	}

	return (s2 << 16) | s1;
}

#pragma endregion zend_adler32

#pragma region IS_SERIALIZED

#define IS_SERIALIZED_INTERNED(ptr) \
	((size_t)(ptr) & Z_UL(1))

/* Allowing == on the upper bound accounts for a potential empty allocation at the end of the
 * memory region. This can also happen for a return-type-only arg_info, where &arg_info[1] is
 * stored, which may point to the end of the region. */
#define IS_SERIALIZED(ptr) \
	((char*)(ptr) <= (char*)script->size)

#define IS_UNSERIALIZED(ptr) \
	(((char*)(ptr) >= (char*)script->mem && (char*)(ptr) <= (char*)script->mem + script->size) || \
	 IS_ACCEL_INTERNED(ptr))

#define SERIALIZE_PTR(ptr) do { \
		if (ptr) { \
			ZEND_ASSERT(IS_UNSERIALIZED(ptr)); \
			(ptr) = (void*)((char*)(ptr) - (char*)script->mem); \
		} \
	} while (0)
#define UNSERIALIZE_PTR(ptr) do { \
		if (ptr) { \
			ZEND_ASSERT(IS_SERIALIZED(ptr)); \
			(ptr) = (void*)((char*)buf + (size_t)(ptr)); \
		} \
	} while (0)
#define SERIALIZE_STR(ptr) do { \
		if (ptr) { \
			if (IS_ACCEL_INTERNED(ptr)) { \
				(ptr) = zend_file_cache_serialize_interned((zend_string*)(ptr), info); \
			} else { \
				ZEND_ASSERT(IS_UNSERIALIZED(ptr)); \
				/* script->corrupted shows if the script in SHM or not */ \
				if (EXPECTED(script->corrupted)) { \
					GC_ADD_FLAGS(ptr, IS_STR_INTERNED); \
					GC_DEL_FLAGS(ptr, IS_STR_PERMANENT); \
				} \
				(ptr) = (void*)((char*)(ptr) - (char*)script->mem); \
			} \
		} \
	} while (0)
#define UNSERIALIZE_STR(ptr) do { \
		if (ptr) { \
			if (IS_SERIALIZED_INTERNED(ptr)) { \
				(ptr) = (void*)zend_file_cache_unserialize_interned((zend_string*)(ptr), !script->corrupted); \
			} else { \
				ZEND_ASSERT(IS_SERIALIZED(ptr)); \
				(ptr) = (void*)((char*)buf + (size_t)(ptr)); \
				/* script->corrupted shows if the script in SHM or not */ \
				if (EXPECTED(!script->corrupted)) { \
					GC_ADD_FLAGS(ptr, IS_STR_INTERNED | IS_STR_PERMANENT); \
				} else { \
					GC_ADD_FLAGS(ptr, IS_STR_INTERNED); \
					GC_DEL_FLAGS(ptr, IS_STR_PERMANENT); \
				} \
			} \
		} \
	} while (0)

#define SERIALIZE_ATTRIBUTES(attributes) do { \
	if ((attributes) && !IS_SERIALIZED(attributes)) { \
		HashTable *ht; \
		SERIALIZE_PTR(attributes); \
		ht = (attributes); \
		UNSERIALIZE_PTR(ht); \
		zend_file_cache_serialize_hash(ht, script, info, buf, zend_file_cache_serialize_attribute); \
	} \
} while (0)

#define UNSERIALIZE_ATTRIBUTES(attributes) do { \
	if ((attributes) && !IS_UNSERIALIZED(attributes)) { \
		HashTable *ht; \
		UNSERIALIZE_PTR(attributes); \
		ht = (attributes); \
		zend_file_cache_unserialize_hash(ht, script, buf, zend_file_cache_unserialize_attribute, NULL); \
	} \
} while (0)

static const uint32_t uninitialized_bucket[-HT_MIN_MASK] =
{ HT_INVALID_IDX, HT_INVALID_IDX };

typedef void (*serialize_callback_t)(zval* zv,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf);

typedef void (*unserialize_callback_t)(zval* zv,
	zend_persistent_script* script,
	void* buf);

static void zend_file_cache_serialize_zval(zval* zv,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf);
static void zend_file_cache_unserialize_zval(zval* zv,
	zend_persistent_script* script,
	void* buf);

static void* zend_file_cache_serialize_interned(zend_string* str,
	zend_file_cache_metainfo* info)
{
	size_t len;
	void* ret;

	/* check if the same interned string was already stored */
	ret = zend_shared_alloc_get_xlat_entry(str);
	if (ret) {
		return ret;
	}

	len = ZEND_MM_ALIGNED_SIZE(_ZSTR_STRUCT_SIZE(ZSTR_LEN(str)));
	ret = (void*)(info->str_size | Z_UL(1));
	zend_shared_alloc_register_xlat_entry(str, ret);

	zend_string* s = (zend_string*)ZCG(mem);
	if (info->str_size + len > ZSTR_LEN(s)) {
		size_t new_len = info->str_size + len;
		s = zend_string_realloc(
			s,
			((_ZSTR_HEADER_SIZE + 1 + new_len + 4095) & ~0xfff) - (_ZSTR_HEADER_SIZE + 1),
			0);
		ZCG(mem) = (void*)s;
	}

	zend_string* new_str = (zend_string*)(ZSTR_VAL(s) + info->str_size);
	memcpy(new_str, str, len);
	GC_ADD_FLAGS(new_str, IS_STR_INTERNED);
	GC_DEL_FLAGS(new_str, IS_STR_PERMANENT | IS_STR_CLASS_NAME_MAP_PTR);
	info->str_size += len;
	return ret;
}

static void* zend_file_cache_unserialize_interned(zend_string* str, bool in_shm)
{
	str = (zend_string*)((char*)ZCG(mem) + ((size_t)(str) & ~Z_UL(1)));
	if (!in_shm) {
		return str;
	}

	zend_string* ret = accel_new_interned_string(str);
	if (ret == str) {
		/* We have to create new SHM allocated string */
		size_t size = _ZSTR_STRUCT_SIZE(ZSTR_LEN(str));
		ret = zend_shared_alloc(size);
		if (!ret) {
			// zend_accel_schedule_restart_if_necessary(ACCEL_RESTART_OOM);
			LONGJMP(*EG(bailout), FAILURE);
		}
		memcpy(ret, str, size);
		/* String wasn't interned but we will use it as interned anyway */
		GC_SET_REFCOUNT(ret, 1);
		GC_TYPE_INFO(ret) = GC_STRING | ((IS_STR_INTERNED | IS_STR_PERSISTENT | IS_STR_PERMANENT) << GC_FLAGS_SHIFT);
	}
	return ret;
}

static void zend_file_cache_serialize_hash(HashTable* ht,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf,
	serialize_callback_t      func)
{
	if (HT_FLAGS(ht) & HASH_FLAG_UNINITIALIZED) {
		ht->arData = NULL;
		return;
	}
	if (IS_SERIALIZED(ht->arData)) {
		return;
	}
	if (HT_IS_PACKED(ht)) {
		zval* p, * end;

		SERIALIZE_PTR(ht->arPacked);
		p = ht->arPacked;
		UNSERIALIZE_PTR(p);
		end = p + ht->nNumUsed;
		while (p < end) {
			if (Z_TYPE_P(p) != IS_UNDEF) {
				func(p, script, info, buf);
			}
			p++;
		}
	}
	else {
		Bucket* p, * end;

		SERIALIZE_PTR(ht->arData);
		p = ht->arData;
		UNSERIALIZE_PTR(p);
		end = p + ht->nNumUsed;
		while (p < end) {
			if (Z_TYPE(p->val) != IS_UNDEF) {
				SERIALIZE_STR(p->key);
				func(&p->val, script, info, buf);
			}
			p++;
		}
	}
}

static void zend_file_cache_serialize_ast(zend_ast* ast,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf)
{
	uint32_t i;
	zend_ast* tmp;

	if (ast->kind == ZEND_AST_ZVAL || ast->kind == ZEND_AST_CONSTANT) {
		zend_file_cache_serialize_zval(&((zend_ast_zval*)ast)->val, script, info, buf);
	}
	else if (zend_ast_is_list(ast)) {
		zend_ast_list* list = zend_ast_get_list(ast);
		for (i = 0; i < list->children; i++) {
			if (list->child[i] && !IS_SERIALIZED(list->child[i])) {
				SERIALIZE_PTR(list->child[i]);
				tmp = list->child[i];
				UNSERIALIZE_PTR(tmp);
				zend_file_cache_serialize_ast(tmp, script, info, buf);
			}
		}
	}
	else {
		uint32_t children = zend_ast_get_num_children(ast);
		for (i = 0; i < children; i++) {
			if (ast->child[i] && !IS_SERIALIZED(ast->child[i])) {
				SERIALIZE_PTR(ast->child[i]);
				tmp = ast->child[i];
				UNSERIALIZE_PTR(tmp);
				zend_file_cache_serialize_ast(tmp, script, info, buf);
			}
		}
	}
}

static void zend_file_cache_serialize_zval(zval* zv,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf)
{
	switch (Z_TYPE_P(zv)) {
	case IS_STRING:
		if (!IS_SERIALIZED(Z_STR_P(zv))) {
			SERIALIZE_STR(Z_STR_P(zv));
		}
		break;
	case IS_ARRAY:
		if (!IS_SERIALIZED(Z_ARR_P(zv))) {
			HashTable* ht;

			SERIALIZE_PTR(Z_ARR_P(zv));
			ht = Z_ARR_P(zv);
			UNSERIALIZE_PTR(ht);
			zend_file_cache_serialize_hash(ht, script, info, buf, zend_file_cache_serialize_zval);
		}
		break;
	case IS_CONSTANT_AST:
		if (!IS_SERIALIZED(Z_AST_P(zv))) {
			zend_ast_ref* ast;

			SERIALIZE_PTR(Z_AST_P(zv));
			ast = Z_AST_P(zv);
			UNSERIALIZE_PTR(ast);
			zend_file_cache_serialize_ast(GC_AST(ast), script, info, buf);
		}
		break;
	case IS_INDIRECT:
		/* Used by static properties. */
		SERIALIZE_PTR(Z_INDIRECT_P(zv));
		break;
	default:
		ZEND_ASSERT(Z_TYPE_P(zv) < IS_STRING);
		break;
	}
}

static void zend_file_cache_serialize_attribute(zval* zv,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf)
{
	zend_attribute* attr = Z_PTR_P(zv);
	uint32_t i;

	SERIALIZE_PTR(Z_PTR_P(zv));
	attr = Z_PTR_P(zv);
	UNSERIALIZE_PTR(attr);

	SERIALIZE_STR(attr->name);
	SERIALIZE_STR(attr->lcname);

	for (i = 0; i < attr->argc; i++) {
		SERIALIZE_STR(attr->args[i].name);
		zend_file_cache_serialize_zval(&attr->args[i].value, script, info, buf);
	}
}

static void zend_file_cache_serialize_type(
	zend_type* type, zend_persistent_script* script, zend_file_cache_metainfo* info, void* buf)
{
	if (ZEND_TYPE_HAS_LIST(*type)) {
		zend_type_list* list = ZEND_TYPE_LIST(*type);
		SERIALIZE_PTR(list);
		ZEND_TYPE_SET_PTR(*type, list);
		UNSERIALIZE_PTR(list);

		zend_type* list_type;
		ZEND_TYPE_LIST_FOREACH(list, list_type) {
			zend_file_cache_serialize_type(list_type, script, info, buf);
		} ZEND_TYPE_LIST_FOREACH_END();
	}
	else if (ZEND_TYPE_HAS_NAME(*type)) {
		zend_string* type_name = ZEND_TYPE_NAME(*type);
		SERIALIZE_STR(type_name);
		ZEND_TYPE_SET_PTR(*type, type_name);
	}
}

static void zend_file_cache_serialize_op_array(zend_op_array* op_array,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf)
{
	ZEND_MAP_PTR_INIT(op_array->static_variables_ptr, NULL);
	ZEND_MAP_PTR_INIT(op_array->run_time_cache, NULL);

	/* Check whether this op_array has already been serialized. */
	if (IS_SERIALIZED(op_array->opcodes)) {
		ZEND_ASSERT(op_array->scope && "Only method op_arrays should be shared");
		return;
	}

	if (op_array->scope) {
		if (UNEXPECTED(zend_shared_alloc_get_xlat_entry(op_array->opcodes))) {
			op_array->refcount = (uint32_t*)(intptr_t)-1;
			SERIALIZE_PTR(op_array->static_variables);
			SERIALIZE_PTR(op_array->literals);
			SERIALIZE_PTR(op_array->opcodes);
			SERIALIZE_PTR(op_array->arg_info);
			SERIALIZE_PTR(op_array->vars);
			SERIALIZE_STR(op_array->function_name);
			SERIALIZE_STR(op_array->filename);
			SERIALIZE_PTR(op_array->live_range);
			SERIALIZE_PTR(op_array->scope);
			SERIALIZE_STR(op_array->doc_comment);
			SERIALIZE_ATTRIBUTES(op_array->attributes);
			SERIALIZE_PTR(op_array->try_catch_array);
			SERIALIZE_PTR(op_array->prototype);
			return;
		}
		zend_shared_alloc_register_xlat_entry(op_array->opcodes, op_array->opcodes);
	}

	if (op_array->static_variables) {
		HashTable* ht;

		SERIALIZE_PTR(op_array->static_variables);
		ht = op_array->static_variables;
		UNSERIALIZE_PTR(ht);
		zend_file_cache_serialize_hash(ht, script, info, buf, zend_file_cache_serialize_zval);
	}

	if (op_array->literals) {
		zval* p, * end;

		SERIALIZE_PTR(op_array->literals);
		p = op_array->literals;
		UNSERIALIZE_PTR(p);
		end = p + op_array->last_literal;
		while (p < end) {
			zend_file_cache_serialize_zval(p, script, info, buf);
			p++;
		}
	}

	{
		zend_op* opline, * end;

#if !ZEND_USE_ABS_CONST_ADDR
		zval* literals = op_array->literals;
		UNSERIALIZE_PTR(literals);
#endif

		SERIALIZE_PTR(op_array->opcodes);
		opline = op_array->opcodes;
		UNSERIALIZE_PTR(opline);
		end = opline + op_array->last;
		while (opline < end) {
#if ZEND_USE_ABS_CONST_ADDR
			if (opline->op1_type == IS_CONST) {
				SERIALIZE_PTR(opline->op1.zv);
			}
			if (opline->op2_type == IS_CONST) {
				SERIALIZE_PTR(opline->op2.zv);
			}
#else
			if (opline->op1_type == IS_CONST) {
				opline->op1.constant = RT_CONSTANT(opline, opline->op1) - literals;
			}
			if (opline->op2_type == IS_CONST) {
				opline->op2.constant = RT_CONSTANT(opline, opline->op2) - literals;
			}
#endif
#if ZEND_USE_ABS_JMP_ADDR
			switch (opline->opcode) {
			case ZEND_JMP:
			case ZEND_FAST_CALL:
				SERIALIZE_PTR(opline->op1.jmp_addr);
				break;
			case ZEND_JMPZ:
			case ZEND_JMPNZ:
			case ZEND_JMPZ_EX:
			case ZEND_JMPNZ_EX:
			case ZEND_JMP_SET:
			case ZEND_COALESCE:
			case ZEND_FE_RESET_R:
			case ZEND_FE_RESET_RW:
			case ZEND_ASSERT_CHECK:
			case ZEND_JMP_NULL:
			case ZEND_BIND_INIT_STATIC_OR_JMP:
				SERIALIZE_PTR(opline->op2.jmp_addr);
				break;
			case ZEND_CATCH:
				if (!(opline->extended_value & ZEND_LAST_CATCH)) {
					SERIALIZE_PTR(opline->op2.jmp_addr);
				}
				break;
			case ZEND_FE_FETCH_R:
			case ZEND_FE_FETCH_RW:
			case ZEND_SWITCH_LONG:
			case ZEND_SWITCH_STRING:
			case ZEND_MATCH:
				/* relative extended_value don't have to be changed */
				break;
			}
#endif
			zend_serialize_opcode_handler(opline);
			opline++;
		}

		if (op_array->arg_info) {
			zend_arg_info* p, * end;
			SERIALIZE_PTR(op_array->arg_info);
			p = op_array->arg_info;
			UNSERIALIZE_PTR(p);
			end = p + op_array->num_args;
			if (op_array->fn_flags & ZEND_ACC_HAS_RETURN_TYPE) {
				p--;
			}
			if (op_array->fn_flags & ZEND_ACC_VARIADIC) {
				end++;
			}
			while (p < end) {
				if (!IS_SERIALIZED(p->name)) {
					SERIALIZE_STR(p->name);
				}
				zend_file_cache_serialize_type(&p->type, script, info, buf);
				p++;
			}
		}

		if (op_array->vars) {
			zend_string** p, ** end;

			SERIALIZE_PTR(op_array->vars);
			p = op_array->vars;
			UNSERIALIZE_PTR(p);
			end = p + op_array->last_var;
			while (p < end) {
				if (!IS_SERIALIZED(*p)) {
					SERIALIZE_STR(*p);
				}
				p++;
			}
		}

		if (op_array->num_dynamic_func_defs) {
			zend_op_array** defs;
			SERIALIZE_PTR(op_array->dynamic_func_defs);
			defs = op_array->dynamic_func_defs;
			UNSERIALIZE_PTR(defs);
			for (uint32_t i = 0; i < op_array->num_dynamic_func_defs; i++) {
				zend_op_array* def;
				SERIALIZE_PTR(defs[i]);
				def = defs[i];
				UNSERIALIZE_PTR(def);
				zend_file_cache_serialize_op_array(def, script, info, buf);
			}
		}

		SERIALIZE_STR(op_array->function_name);
		SERIALIZE_STR(op_array->filename);
		SERIALIZE_PTR(op_array->live_range);
		SERIALIZE_PTR(op_array->scope);
		SERIALIZE_STR(op_array->doc_comment);
		SERIALIZE_ATTRIBUTES(op_array->attributes);
		SERIALIZE_PTR(op_array->try_catch_array);
		SERIALIZE_PTR(op_array->prototype);
	}
}

static void zend_file_cache_serialize_func(zval* zv,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf)
{
	zend_function* func;
	SERIALIZE_PTR(Z_PTR_P(zv));
	func = Z_PTR_P(zv);
	UNSERIALIZE_PTR(func);
	ZEND_ASSERT(func->type == ZEND_USER_FUNCTION);
	zend_file_cache_serialize_op_array(&func->op_array, script, info, buf);
}

static void zend_file_cache_serialize_prop_info(zval* zv,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf)
{
	if (!IS_SERIALIZED(Z_PTR_P(zv))) {
		zend_property_info* prop;

		SERIALIZE_PTR(Z_PTR_P(zv));
		prop = Z_PTR_P(zv);
		UNSERIALIZE_PTR(prop);

		ZEND_ASSERT(prop->ce != NULL && prop->name != NULL);
		if (!IS_SERIALIZED(prop->ce)) {
			SERIALIZE_PTR(prop->ce);
			SERIALIZE_STR(prop->name);
			if (prop->doc_comment) {
				SERIALIZE_STR(prop->doc_comment);
			}
			SERIALIZE_ATTRIBUTES(prop->attributes);
			zend_file_cache_serialize_type(&prop->type, script, info, buf);
		}
	}
}

static void zend_file_cache_serialize_class_constant(zval* zv,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf)
{
	if (!IS_SERIALIZED(Z_PTR_P(zv))) {
		zend_class_constant* c;

		SERIALIZE_PTR(Z_PTR_P(zv));
		c = Z_PTR_P(zv);
		UNSERIALIZE_PTR(c);

		ZEND_ASSERT(c->ce != NULL);
		if (!IS_SERIALIZED(c->ce)) {
			SERIALIZE_PTR(c->ce);

			zend_file_cache_serialize_zval(&c->value, script, info, buf);
			if (c->doc_comment) {
				SERIALIZE_STR(c->doc_comment);
			}

			SERIALIZE_ATTRIBUTES(c->attributes);
			zend_file_cache_serialize_type(&c->type, script, info, buf);
		}
	}
}

static void zend_file_cache_serialize_class(zval* zv,
	zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf)
{
	zend_class_entry* ce;

	SERIALIZE_PTR(Z_PTR_P(zv));
	ce = Z_PTR_P(zv);
	UNSERIALIZE_PTR(ce);

	SERIALIZE_STR(ce->name);
	if (ce->parent) {
		if (!(ce->ce_flags & ZEND_ACC_LINKED)) {
			SERIALIZE_STR(ce->parent_name);
		}
		else {
			SERIALIZE_PTR(ce->parent);
		}
	}
	zend_file_cache_serialize_hash(&ce->function_table, script, info, buf, zend_file_cache_serialize_func);
	if (ce->default_properties_table) {
		zval* p, * end;

		SERIALIZE_PTR(ce->default_properties_table);
		p = ce->default_properties_table;
		UNSERIALIZE_PTR(p);
		end = p + ce->default_properties_count;
		while (p < end) {
			zend_file_cache_serialize_zval(p, script, info, buf);
			p++;
		}
	}
	if (ce->default_static_members_table) {
		zval* p, * end;

		SERIALIZE_PTR(ce->default_static_members_table);
		p = ce->default_static_members_table;
		UNSERIALIZE_PTR(p);

		end = p + ce->default_static_members_count;
		while (p < end) {
			zend_file_cache_serialize_zval(p, script, info, buf);
			p++;
		}
	}
	zend_file_cache_serialize_hash(&ce->constants_table, script, info, buf, zend_file_cache_serialize_class_constant);
	SERIALIZE_STR(ce->info.user.filename);
	SERIALIZE_STR(ce->info.user.doc_comment);
	SERIALIZE_ATTRIBUTES(ce->attributes);
	zend_file_cache_serialize_hash(&ce->properties_info, script, info, buf, zend_file_cache_serialize_prop_info);

	if (ce->properties_info_table) {
		uint32_t i;
		zend_property_info** table;

		SERIALIZE_PTR(ce->properties_info_table);
		table = ce->properties_info_table;
		UNSERIALIZE_PTR(table);

		for (i = 0; i < ce->default_properties_count; i++) {
			SERIALIZE_PTR(table[i]);
		}
	}

	if (ce->num_interfaces) {
		uint32_t i;
		zend_class_name* interface_names;

		ZEND_ASSERT(!(ce->ce_flags & ZEND_ACC_LINKED));

		SERIALIZE_PTR(ce->interface_names);
		interface_names = ce->interface_names;
		UNSERIALIZE_PTR(interface_names);

		for (i = 0; i < ce->num_interfaces; i++) {
			SERIALIZE_STR(interface_names[i].name);
			SERIALIZE_STR(interface_names[i].lc_name);
		}
	}

	if (ce->num_traits) {
		uint32_t i;
		zend_class_name* trait_names;

		SERIALIZE_PTR(ce->trait_names);
		trait_names = ce->trait_names;
		UNSERIALIZE_PTR(trait_names);

		for (i = 0; i < ce->num_traits; i++) {
			SERIALIZE_STR(trait_names[i].name);
			SERIALIZE_STR(trait_names[i].lc_name);
		}

		if (ce->trait_aliases) {
			zend_trait_alias** p, * q;

			SERIALIZE_PTR(ce->trait_aliases);
			p = ce->trait_aliases;
			UNSERIALIZE_PTR(p);

			while (*p) {
				SERIALIZE_PTR(*p);
				q = *p;
				UNSERIALIZE_PTR(q);

				if (q->trait_method.method_name) {
					SERIALIZE_STR(q->trait_method.method_name);
				}
				if (q->trait_method.class_name) {
					SERIALIZE_STR(q->trait_method.class_name);
				}

				if (q->alias) {
					SERIALIZE_STR(q->alias);
				}
				p++;
			}
		}

		if (ce->trait_precedences) {
			zend_trait_precedence** p, * q;
			uint32_t j;

			SERIALIZE_PTR(ce->trait_precedences);
			p = ce->trait_precedences;
			UNSERIALIZE_PTR(p);

			while (*p) {
				SERIALIZE_PTR(*p);
				q = *p;
				UNSERIALIZE_PTR(q);

				if (q->trait_method.method_name) {
					SERIALIZE_STR(q->trait_method.method_name);
				}
				if (q->trait_method.class_name) {
					SERIALIZE_STR(q->trait_method.class_name);
				}

				for (j = 0; j < q->num_excludes; j++) {
					SERIALIZE_STR(q->exclude_class_names[j]);
				}
				p++;
			}
		}
	}

	SERIALIZE_PTR(ce->constructor);
	SERIALIZE_PTR(ce->destructor);
	SERIALIZE_PTR(ce->clone);
	SERIALIZE_PTR(ce->__get);
	SERIALIZE_PTR(ce->__set);
	SERIALIZE_PTR(ce->__call);
	SERIALIZE_PTR(ce->__serialize);
	SERIALIZE_PTR(ce->__unserialize);
	SERIALIZE_PTR(ce->__isset);
	SERIALIZE_PTR(ce->__unset);
	SERIALIZE_PTR(ce->__tostring);
	SERIALIZE_PTR(ce->__callstatic);
	SERIALIZE_PTR(ce->__debugInfo);

	if (ce->iterator_funcs_ptr) {
		SERIALIZE_PTR(ce->iterator_funcs_ptr->zf_new_iterator);
		SERIALIZE_PTR(ce->iterator_funcs_ptr->zf_rewind);
		SERIALIZE_PTR(ce->iterator_funcs_ptr->zf_valid);
		SERIALIZE_PTR(ce->iterator_funcs_ptr->zf_key);
		SERIALIZE_PTR(ce->iterator_funcs_ptr->zf_current);
		SERIALIZE_PTR(ce->iterator_funcs_ptr->zf_next);
		SERIALIZE_PTR(ce->iterator_funcs_ptr);
	}

	if (ce->arrayaccess_funcs_ptr) {
		SERIALIZE_PTR(ce->arrayaccess_funcs_ptr->zf_offsetget);
		SERIALIZE_PTR(ce->arrayaccess_funcs_ptr->zf_offsetexists);
		SERIALIZE_PTR(ce->arrayaccess_funcs_ptr->zf_offsetset);
		SERIALIZE_PTR(ce->arrayaccess_funcs_ptr->zf_offsetunset);
		SERIALIZE_PTR(ce->arrayaccess_funcs_ptr);
	}

	ZEND_MAP_PTR_INIT(ce->static_members_table, NULL);
	ZEND_MAP_PTR_INIT(ce->mutable_data, NULL);

	ce->inheritance_cache = NULL;
}

static void zend_file_cache_serialize_warnings(
	zend_persistent_script* script, zend_file_cache_metainfo* info, void* buf)
{
	if (script->warnings) {
		zend_error_info** warnings;
		SERIALIZE_PTR(script->warnings);
		warnings = script->warnings;
		UNSERIALIZE_PTR(warnings);

		for (uint32_t i = 0; i < script->num_warnings; i++) {
			zend_error_info* warning;
			SERIALIZE_PTR(warnings[i]);
			warning = warnings[i];
			UNSERIALIZE_PTR(warning);
			SERIALIZE_STR(warning->filename);
			SERIALIZE_STR(warning->message);
		}
	}
}

static void zend_file_cache_serialize_early_bindings(
	zend_persistent_script* script, zend_file_cache_metainfo* info, void* buf)
{
	if (script->early_bindings) {
		SERIALIZE_PTR(script->early_bindings);
		zend_early_binding* early_bindings = script->early_bindings;
		UNSERIALIZE_PTR(early_bindings);
		for (uint32_t i = 0; i < script->num_early_bindings; i++) {
			SERIALIZE_STR(early_bindings[i].lcname);
			SERIALIZE_STR(early_bindings[i].rtd_key);
			SERIALIZE_STR(early_bindings[i].lc_parent_name);
		}
	}
}

static void zend_file_cache_serialize(zend_persistent_script* script,
	zend_file_cache_metainfo* info,
	void* buf)
{
	zend_persistent_script* new_script;

	memcpy(info->magic, "OPCACHE", 8);
	memcpy(info->system_id, zend_system_id, 32);
	info->mem_size = script->size;
	info->str_size = 0;
	info->script_offset = (char*)script - (char*)script->mem;
	info->timestamp = script->timestamp;

	memcpy(buf, script->mem, script->size);

	new_script = (zend_persistent_script*)((char*)buf + info->script_offset);
	SERIALIZE_STR(new_script->script.filename);

	zend_file_cache_serialize_hash(&new_script->script.class_table, script, info, buf, zend_file_cache_serialize_class);
	zend_file_cache_serialize_hash(&new_script->script.function_table, script, info, buf, zend_file_cache_serialize_func);
	zend_file_cache_serialize_op_array(&new_script->script.main_op_array, script, info, buf);
	zend_file_cache_serialize_warnings(new_script, info, buf);
	zend_file_cache_serialize_early_bindings(new_script, info, buf);

	new_script->mem = NULL;
}

#pragma endregion IS_SERIALIZED

#pragma region zend_file_cache_unserialize_hash

static void zend_file_cache_unserialize_hash(HashTable* ht,
	zend_persistent_script* script,
	void* buf,
	unserialize_callback_t   func,
	dtor_func_t              dtor)
{
	ht->pDestructor = dtor;
	if (HT_FLAGS(ht) & HASH_FLAG_UNINITIALIZED) {
		HT_SET_DATA_ADDR(ht, &uninitialized_bucket);
		return;
	}
	if (IS_UNSERIALIZED(ht->arData)) {
		return;
	}
	UNSERIALIZE_PTR(ht->arData);
	if (HT_IS_PACKED(ht)) {
		zval* p, * end;

		p = ht->arPacked;
		end = p + ht->nNumUsed;
		while (p < end) {
			if (Z_TYPE_P(p) != IS_UNDEF) {
				func(p, script, buf);
			}
			p++;
		}
	}
	else {
		Bucket* p, * end;

		p = ht->arData;
		end = p + ht->nNumUsed;
		while (p < end) {
			if (Z_TYPE(p->val) != IS_UNDEF) {
				UNSERIALIZE_STR(p->key);
				func(&p->val, script, buf);
			}
			p++;
		}
	}
}

static void zend_file_cache_unserialize_ast(zend_ast* ast,
	zend_persistent_script* script,
	void* buf)
{
	uint32_t i;

	if (ast->kind == ZEND_AST_ZVAL || ast->kind == ZEND_AST_CONSTANT) {
		zend_file_cache_unserialize_zval(&((zend_ast_zval*)ast)->val, script, buf);
	}
	else if (zend_ast_is_list(ast)) {
		zend_ast_list* list = zend_ast_get_list(ast);
		for (i = 0; i < list->children; i++) {
			if (list->child[i] && !IS_UNSERIALIZED(list->child[i])) {
				UNSERIALIZE_PTR(list->child[i]);
				zend_file_cache_unserialize_ast(list->child[i], script, buf);
			}
		}
	}
	else {
		uint32_t children = zend_ast_get_num_children(ast);
		for (i = 0; i < children; i++) {
			if (ast->child[i] && !IS_UNSERIALIZED(ast->child[i])) {
				UNSERIALIZE_PTR(ast->child[i]);
				zend_file_cache_unserialize_ast(ast->child[i], script, buf);
			}
		}
	}
}

static void zend_file_cache_unserialize_zval(zval* zv,
	zend_persistent_script* script,
	void* buf)
{
	switch (Z_TYPE_P(zv)) {
	case IS_STRING:
		/* We can't use !IS_UNSERIALIZED here, because that does not recognize unserialized
		 * interned strings in non-shm mode. */
		if (IS_SERIALIZED(Z_STR_P(zv)) || IS_SERIALIZED_INTERNED(Z_STR_P(zv))) {
			UNSERIALIZE_STR(Z_STR_P(zv));
		}
		break;
	case IS_ARRAY:
		if (!IS_UNSERIALIZED(Z_ARR_P(zv))) {
			HashTable* ht;

			UNSERIALIZE_PTR(Z_ARR_P(zv));
			ht = Z_ARR_P(zv);
			zend_file_cache_unserialize_hash(ht,
				script, buf, zend_file_cache_unserialize_zval, ZVAL_PTR_DTOR);
		}
		break;
	case IS_CONSTANT_AST:
		if (!IS_UNSERIALIZED(Z_AST_P(zv))) {
			UNSERIALIZE_PTR(Z_AST_P(zv));
			zend_file_cache_unserialize_ast(Z_ASTVAL_P(zv), script, buf);
		}
		break;
	case IS_INDIRECT:
		/* Used by static properties. */
		UNSERIALIZE_PTR(Z_INDIRECT_P(zv));
		break;
	default:
		ZEND_ASSERT(Z_TYPE_P(zv) < IS_STRING);
		break;
	}
}

static void zend_file_cache_unserialize_attribute(zval* zv, zend_persistent_script* script, void* buf)
{
	zend_attribute* attr;
	uint32_t i;

	UNSERIALIZE_PTR(Z_PTR_P(zv));
	attr = Z_PTR_P(zv);

	UNSERIALIZE_STR(attr->name);
	UNSERIALIZE_STR(attr->lcname);

	for (i = 0; i < attr->argc; i++) {
		UNSERIALIZE_STR(attr->args[i].name);
		zend_file_cache_unserialize_zval(&attr->args[i].value, script, buf);
	}
}

static void zend_file_cache_unserialize_type(
	zend_type* type, zend_class_entry* scope, zend_persistent_script* script, void* buf)
{
	if (ZEND_TYPE_HAS_LIST(*type)) {
		zend_type_list* list = ZEND_TYPE_LIST(*type);
		UNSERIALIZE_PTR(list);
		ZEND_TYPE_SET_PTR(*type, list);

		zend_type* list_type;
		ZEND_TYPE_LIST_FOREACH(list, list_type) {
			zend_file_cache_unserialize_type(list_type, scope, script, buf);
		} ZEND_TYPE_LIST_FOREACH_END();
	}
	else if (ZEND_TYPE_HAS_NAME(*type)) {
		zend_string* type_name = ZEND_TYPE_NAME(*type);
		UNSERIALIZE_STR(type_name);
		ZEND_TYPE_SET_PTR(*type, type_name);
		if (!script->corrupted) {
			zend_accel_get_class_name_map_ptr(type_name);
		}
		else {
			zend_alloc_ce_cache(type_name);
		}
	}
}

static void zend_file_cache_unserialize_op_array(zend_op_array* op_array,
	zend_persistent_script* script,
	void* buf)
{
	if (!script->corrupted) {
		if (op_array != &script->script.main_op_array) {
			op_array->fn_flags |= ZEND_ACC_IMMUTABLE;
			ZEND_MAP_PTR_NEW(op_array->run_time_cache);
		}
		else {
			ZEND_ASSERT(!(op_array->fn_flags & ZEND_ACC_IMMUTABLE));
			ZEND_MAP_PTR_INIT(op_array->run_time_cache, NULL);
		}
		if (op_array->static_variables) {
			ZEND_MAP_PTR_NEW(op_array->static_variables_ptr);
		}
	}
	else {
		op_array->fn_flags &= ~ZEND_ACC_IMMUTABLE;
		ZEND_MAP_PTR_INIT(op_array->static_variables_ptr, NULL);
		ZEND_MAP_PTR_INIT(op_array->run_time_cache, NULL);
	}

	/* Check whether this op_array has already been unserialized. */
	if (IS_UNSERIALIZED(op_array->opcodes)) {
		ZEND_ASSERT(op_array->scope && "Only method op_arrays should be shared");
		return;
	}

	if (op_array->refcount) {
		op_array->refcount = NULL;
		UNSERIALIZE_PTR(op_array->static_variables);
		UNSERIALIZE_PTR(op_array->literals);
		UNSERIALIZE_PTR(op_array->opcodes);
		UNSERIALIZE_PTR(op_array->arg_info);
		UNSERIALIZE_PTR(op_array->vars);
		UNSERIALIZE_STR(op_array->function_name);
		UNSERIALIZE_STR(op_array->filename);
		UNSERIALIZE_PTR(op_array->live_range);
		UNSERIALIZE_PTR(op_array->scope);
		UNSERIALIZE_STR(op_array->doc_comment);
		UNSERIALIZE_ATTRIBUTES(op_array->attributes);
		UNSERIALIZE_PTR(op_array->try_catch_array);
		UNSERIALIZE_PTR(op_array->prototype);
		return;
	}

	if (op_array->static_variables) {
		HashTable* ht;

		UNSERIALIZE_PTR(op_array->static_variables);
		ht = op_array->static_variables;
		zend_file_cache_unserialize_hash(ht,
			script, buf, zend_file_cache_unserialize_zval, ZVAL_PTR_DTOR);
	}

	if (op_array->literals) {
		zval* p, * end;

		UNSERIALIZE_PTR(op_array->literals);
		p = op_array->literals;
		end = p + op_array->last_literal;
		while (p < end) {
			zend_file_cache_unserialize_zval(p, script, buf);
			p++;
		}
	}

	{
		zend_op* opline, * end;

		UNSERIALIZE_PTR(op_array->opcodes);
		opline = op_array->opcodes;
		end = opline + op_array->last;
		while (opline < end) {
#if ZEND_USE_ABS_CONST_ADDR
			if (opline->op1_type == IS_CONST) {
				UNSERIALIZE_PTR(opline->op1.zv);
			}
			if (opline->op2_type == IS_CONST) {
				UNSERIALIZE_PTR(opline->op2.zv);
			}
#else
			if (opline->op1_type == IS_CONST) {
				ZEND_PASS_TWO_UPDATE_CONSTANT(op_array, opline, opline->op1);
			}
			if (opline->op2_type == IS_CONST) {
				ZEND_PASS_TWO_UPDATE_CONSTANT(op_array, opline, opline->op2);
			}
#endif
#if ZEND_USE_ABS_JMP_ADDR
			switch (opline->opcode) {
			case ZEND_JMP:
			case ZEND_FAST_CALL:
				UNSERIALIZE_PTR(opline->op1.jmp_addr);
				break;
			case ZEND_JMPZ:
			case ZEND_JMPNZ:
			case ZEND_JMPZ_EX:
			case ZEND_JMPNZ_EX:
			case ZEND_JMP_SET:
			case ZEND_COALESCE:
			case ZEND_FE_RESET_R:
			case ZEND_FE_RESET_RW:
			case ZEND_ASSERT_CHECK:
			case ZEND_JMP_NULL:
			case ZEND_BIND_INIT_STATIC_OR_JMP:
				UNSERIALIZE_PTR(opline->op2.jmp_addr);
				break;
			case ZEND_CATCH:
				if (!(opline->extended_value & ZEND_LAST_CATCH)) {
					UNSERIALIZE_PTR(opline->op2.jmp_addr);
				}
				break;
			case ZEND_FE_FETCH_R:
			case ZEND_FE_FETCH_RW:
			case ZEND_SWITCH_LONG:
			case ZEND_SWITCH_STRING:
				/* relative extended_value don't have to be changed */
				break;
			}
#endif
			zend_deserialize_opcode_handler(opline);
			opline++;
		}

		UNSERIALIZE_PTR(op_array->scope);

		if (op_array->arg_info) {
			zend_arg_info* p, * end;
			UNSERIALIZE_PTR(op_array->arg_info);
			p = op_array->arg_info;
			end = p + op_array->num_args;
			if (op_array->fn_flags & ZEND_ACC_HAS_RETURN_TYPE) {
				p--;
			}
			if (op_array->fn_flags & ZEND_ACC_VARIADIC) {
				end++;
			}
			while (p < end) {
				if (!IS_UNSERIALIZED(p->name)) {
					UNSERIALIZE_STR(p->name);
				}
				zend_file_cache_unserialize_type(&p->type, (op_array->fn_flags & ZEND_ACC_CLOSURE) ? NULL : op_array->scope, script, buf);
				p++;
			}
		}

		if (op_array->vars) {
			zend_string** p, ** end;

			UNSERIALIZE_PTR(op_array->vars);
			p = op_array->vars;
			end = p + op_array->last_var;
			while (p < end) {
				if (!IS_UNSERIALIZED(*p)) {
					UNSERIALIZE_STR(*p);
				}
				p++;
			}
		}

		if (op_array->num_dynamic_func_defs) {
			UNSERIALIZE_PTR(op_array->dynamic_func_defs);
			for (uint32_t i = 0; i < op_array->num_dynamic_func_defs; i++) {
				UNSERIALIZE_PTR(op_array->dynamic_func_defs[i]);
				zend_file_cache_unserialize_op_array(op_array->dynamic_func_defs[i], script, buf);
			}
		}

		UNSERIALIZE_STR(op_array->function_name);
		UNSERIALIZE_STR(op_array->filename);
		UNSERIALIZE_PTR(op_array->live_range);
		UNSERIALIZE_STR(op_array->doc_comment);
		UNSERIALIZE_ATTRIBUTES(op_array->attributes);
		UNSERIALIZE_PTR(op_array->try_catch_array);
		UNSERIALIZE_PTR(op_array->prototype);
	}
}

static void zend_file_cache_unserialize_func(zval* zv,
	zend_persistent_script* script,
	void* buf)
{
	zend_function* func;
	UNSERIALIZE_PTR(Z_PTR_P(zv));
	func = Z_PTR_P(zv);
	ZEND_ASSERT(func->type == ZEND_USER_FUNCTION);
	zend_file_cache_unserialize_op_array(&func->op_array, script, buf);
}

static void zend_file_cache_unserialize_prop_info(zval* zv,
	zend_persistent_script* script,
	void* buf)
{
	if (!IS_UNSERIALIZED(Z_PTR_P(zv))) {
		zend_property_info* prop;

		UNSERIALIZE_PTR(Z_PTR_P(zv));
		prop = Z_PTR_P(zv);

		ZEND_ASSERT(prop->ce != NULL && prop->name != NULL);
		if (!IS_UNSERIALIZED(prop->ce)) {
			UNSERIALIZE_PTR(prop->ce);
			UNSERIALIZE_STR(prop->name);
			if (prop->doc_comment) {
				UNSERIALIZE_STR(prop->doc_comment);
			}
			UNSERIALIZE_ATTRIBUTES(prop->attributes);
			zend_file_cache_unserialize_type(&prop->type, prop->ce, script, buf);
		}
	}
}

static void zend_file_cache_unserialize_class_constant(zval* zv,
	zend_persistent_script* script,
	void* buf)
{
	if (!IS_UNSERIALIZED(Z_PTR_P(zv))) {
		zend_class_constant* c;

		UNSERIALIZE_PTR(Z_PTR_P(zv));
		c = Z_PTR_P(zv);

		ZEND_ASSERT(c->ce != NULL);
		if (!IS_UNSERIALIZED(c->ce)) {
			UNSERIALIZE_PTR(c->ce);

			zend_file_cache_unserialize_zval(&c->value, script, buf);

			if (c->doc_comment) {
				UNSERIALIZE_STR(c->doc_comment);
			}
			UNSERIALIZE_ATTRIBUTES(c->attributes);
			zend_file_cache_unserialize_type(&c->type, c->ce, script, buf);
		}
	}
}

static void zend_file_cache_unserialize_class(zval* zv,
	zend_persistent_script* script,
	void* buf)
{
	zend_class_entry* ce;

	UNSERIALIZE_PTR(Z_PTR_P(zv));
	ce = Z_PTR_P(zv);

	UNSERIALIZE_STR(ce->name);
	if (!(ce->ce_flags & ZEND_ACC_ANON_CLASS)) {
		if (!script->corrupted) {
			zend_accel_get_class_name_map_ptr(ce->name);
		}
		else {
			zend_alloc_ce_cache(ce->name);
		}
	}
	if (ce->parent) {
		if (!(ce->ce_flags & ZEND_ACC_LINKED)) {
			UNSERIALIZE_STR(ce->parent_name);
		}
		else {
			UNSERIALIZE_PTR(ce->parent);
		}
	}
	zend_file_cache_unserialize_hash(&ce->function_table,
		script, buf, zend_file_cache_unserialize_func, ZEND_FUNCTION_DTOR);
	if (ce->default_properties_table) {
		zval* p, * end;

		UNSERIALIZE_PTR(ce->default_properties_table);
		p = ce->default_properties_table;
		end = p + ce->default_properties_count;
		while (p < end) {
			zend_file_cache_unserialize_zval(p, script, buf);
			p++;
		}
	}
	if (ce->default_static_members_table) {
		zval* p, * end;
		UNSERIALIZE_PTR(ce->default_static_members_table);
		p = ce->default_static_members_table;
		end = p + ce->default_static_members_count;
		while (p < end) {
			zend_file_cache_unserialize_zval(p, script, buf);
			p++;
		}
	}
	zend_file_cache_unserialize_hash(&ce->constants_table,
		script, buf, zend_file_cache_unserialize_class_constant, NULL);
	UNSERIALIZE_STR(ce->info.user.filename);
	UNSERIALIZE_STR(ce->info.user.doc_comment);
	UNSERIALIZE_ATTRIBUTES(ce->attributes);
	zend_file_cache_unserialize_hash(&ce->properties_info,
		script, buf, zend_file_cache_unserialize_prop_info, NULL);

	if (ce->properties_info_table) {
		uint32_t i;
		UNSERIALIZE_PTR(ce->properties_info_table);

		for (i = 0; i < ce->default_properties_count; i++) {
			UNSERIALIZE_PTR(ce->properties_info_table[i]);
		}
	}

	if (ce->num_interfaces) {
		uint32_t i;

		ZEND_ASSERT(!(ce->ce_flags & ZEND_ACC_LINKED));
		UNSERIALIZE_PTR(ce->interface_names);

		for (i = 0; i < ce->num_interfaces; i++) {
			UNSERIALIZE_STR(ce->interface_names[i].name);
			UNSERIALIZE_STR(ce->interface_names[i].lc_name);
		}
	}

	if (ce->num_traits) {
		uint32_t i;

		UNSERIALIZE_PTR(ce->trait_names);

		for (i = 0; i < ce->num_traits; i++) {
			UNSERIALIZE_STR(ce->trait_names[i].name);
			UNSERIALIZE_STR(ce->trait_names[i].lc_name);
		}

		if (ce->trait_aliases) {
			zend_trait_alias** p, * q;

			UNSERIALIZE_PTR(ce->trait_aliases);
			p = ce->trait_aliases;

			while (*p) {
				UNSERIALIZE_PTR(*p);
				q = *p;

				if (q->trait_method.method_name) {
					UNSERIALIZE_STR(q->trait_method.method_name);
				}
				if (q->trait_method.class_name) {
					UNSERIALIZE_STR(q->trait_method.class_name);
				}

				if (q->alias) {
					UNSERIALIZE_STR(q->alias);
				}
				p++;
			}
		}

		if (ce->trait_precedences) {
			zend_trait_precedence** p, * q;
			uint32_t j;

			UNSERIALIZE_PTR(ce->trait_precedences);
			p = ce->trait_precedences;

			while (*p) {
				UNSERIALIZE_PTR(*p);
				q = *p;

				if (q->trait_method.method_name) {
					UNSERIALIZE_STR(q->trait_method.method_name);
				}
				if (q->trait_method.class_name) {
					UNSERIALIZE_STR(q->trait_method.class_name);
				}

				for (j = 0; j < q->num_excludes; j++) {
					UNSERIALIZE_STR(q->exclude_class_names[j]);
				}
				p++;
			}
		}
	}

	UNSERIALIZE_PTR(ce->constructor);
	UNSERIALIZE_PTR(ce->destructor);
	UNSERIALIZE_PTR(ce->clone);
	UNSERIALIZE_PTR(ce->__get);
	UNSERIALIZE_PTR(ce->__set);
	UNSERIALIZE_PTR(ce->__call);
	UNSERIALIZE_PTR(ce->__serialize);
	UNSERIALIZE_PTR(ce->__unserialize);
	UNSERIALIZE_PTR(ce->__isset);
	UNSERIALIZE_PTR(ce->__unset);
	UNSERIALIZE_PTR(ce->__tostring);
	UNSERIALIZE_PTR(ce->__callstatic);
	UNSERIALIZE_PTR(ce->__debugInfo);

	if (ce->iterator_funcs_ptr) {
		UNSERIALIZE_PTR(ce->iterator_funcs_ptr);
		UNSERIALIZE_PTR(ce->iterator_funcs_ptr->zf_new_iterator);
		UNSERIALIZE_PTR(ce->iterator_funcs_ptr->zf_rewind);
		UNSERIALIZE_PTR(ce->iterator_funcs_ptr->zf_valid);
		UNSERIALIZE_PTR(ce->iterator_funcs_ptr->zf_key);
		UNSERIALIZE_PTR(ce->iterator_funcs_ptr->zf_current);
		UNSERIALIZE_PTR(ce->iterator_funcs_ptr->zf_next);
	}
	if (ce->arrayaccess_funcs_ptr) {
		UNSERIALIZE_PTR(ce->arrayaccess_funcs_ptr);
		UNSERIALIZE_PTR(ce->arrayaccess_funcs_ptr->zf_offsetget);
		UNSERIALIZE_PTR(ce->arrayaccess_funcs_ptr->zf_offsetexists);
		UNSERIALIZE_PTR(ce->arrayaccess_funcs_ptr->zf_offsetset);
		UNSERIALIZE_PTR(ce->arrayaccess_funcs_ptr->zf_offsetunset);
	}

	if (!(script->corrupted)) {
		ce->ce_flags |= ZEND_ACC_IMMUTABLE;
		ce->ce_flags &= ~ZEND_ACC_FILE_CACHED;
		ZEND_MAP_PTR_NEW(ce->mutable_data);
		if (ce->default_static_members_count) {
			ZEND_MAP_PTR_NEW(ce->static_members_table);
		}
	}
	else {
		ce->ce_flags &= ~ZEND_ACC_IMMUTABLE;
		ce->ce_flags |= ZEND_ACC_FILE_CACHED;
		ZEND_MAP_PTR_INIT(ce->mutable_data, NULL);
		ZEND_MAP_PTR_INIT(ce->static_members_table, NULL);
	}

	// Memory addresses of object handlers are not stable. They can change due to ASLR or order of linking dynamic. To
	// avoid pointing to invalid memory we relink default_object_handlers here.
	ce->default_object_handlers = ce->ce_flags & ZEND_ACC_ENUM ? &zend_enum_object_handlers : &std_object_handlers;
}

static void zend_file_cache_unserialize_warnings(zend_persistent_script* script, void* buf)
{
	if (script->warnings) {
		UNSERIALIZE_PTR(script->warnings);
		for (uint32_t i = 0; i < script->num_warnings; i++) {
			UNSERIALIZE_PTR(script->warnings[i]);
			UNSERIALIZE_STR(script->warnings[i]->filename);
			UNSERIALIZE_STR(script->warnings[i]->message);
		}
	}
}

static void zend_file_cache_unserialize_early_bindings(zend_persistent_script* script, void* buf)
{
	if (script->early_bindings) {
		UNSERIALIZE_PTR(script->early_bindings);
		for (uint32_t i = 0; i < script->num_early_bindings; i++) {
			UNSERIALIZE_STR(script->early_bindings[i].lcname);
			UNSERIALIZE_STR(script->early_bindings[i].rtd_key);
			UNSERIALIZE_STR(script->early_bindings[i].lc_parent_name);
		}
	}
}

static void zend_file_cache_unserialize(zend_persistent_script* script,
	void* buf)
{
	script->mem = buf;

	UNSERIALIZE_STR(script->script.filename);

	zend_file_cache_unserialize_hash(&script->script.class_table,
		script, buf, zend_file_cache_unserialize_class, ZEND_CLASS_DTOR);
	zend_file_cache_unserialize_hash(&script->script.function_table,
		script, buf, zend_file_cache_unserialize_func, ZEND_FUNCTION_DTOR);
	zend_file_cache_unserialize_op_array(&script->script.main_op_array, script, buf);
	zend_file_cache_unserialize_warnings(script, buf);
	zend_file_cache_unserialize_early_bindings(script, buf);
}

#pragma endregion zend_file_cache_unserialize_hash

#pragma region zend_file_cache_mkdir

#ifndef ZEND_WIN32
#define zend_file_cache_unlink unlink
#define zend_file_cache_open open
#else
#define zend_file_cache_unlink php_win32_ioutil_unlink
#define zend_file_cache_open php_win32_ioutil_open
#endif

#ifdef ZEND_WIN32
# define LOCK_SH 0
# define LOCK_EX 1
# define LOCK_UN 2
static int zend_file_cache_flock(int fd, int op)
{
	OVERLAPPED offset = { 0,0,0,0,NULL };
	if (op == LOCK_EX) {
		if (LockFileEx((HANDLE)_get_osfhandle(fd),
			LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &offset) == TRUE) {
			return 0;
		}
	}
	else if (op == LOCK_SH) {
		if (LockFileEx((HANDLE)_get_osfhandle(fd),
			0, 0, 1, 0, &offset) == TRUE) {
			return 0;
		}
	}
	else if (op == LOCK_UN) {
		if (UnlockFileEx((HANDLE)_get_osfhandle(fd),
			0, 1, 0, &offset) == TRUE) {
			return 0;
		}
	}
	return -1;
}
#elif defined(HAVE_FLOCK)
# define zend_file_cache_flock flock
#else
# define LOCK_SH 0
# define LOCK_EX 1
# define LOCK_UN 2
static int zend_file_cache_flock(int fd, int type)
{
	return 0;
}
#endif


#ifdef ZEND_WIN32
static zend_result accel_gen_uname_id(void)
{
	PHP_MD5_CTX ctx;
	unsigned char digest[16];
	wchar_t uname[UNLEN + 1];
	DWORD unsize = UNLEN;

	if (!GetUserNameW(uname, &unsize)) {
		return FAILURE;
	}
	PHP_MD5Init(&ctx);
	PHP_MD5Update(&ctx, (void*)uname, (unsize - 1) * sizeof(wchar_t));
	PHP_MD5Update(&ctx, ZCG(accel_directives).cache_id, strlen(ZCG(accel_directives).cache_id));
	PHP_MD5Final(digest, &ctx);
	php_hash_bin2hex(accel_uname_id, digest, sizeof digest);
	return SUCCESS;
}
#endif

static int zend_file_cache_mkdir(char* filename, size_t start)
{
	char* s = filename + start;

	while (*s) {
		if (IS_SLASH(*s)) {
			char old = *s;
			*s = '\000';
#ifndef ZEND_WIN32
			if (mkdir(filename, S_IRWXU) < 0 && errno != EEXIST) {
#else
			if (php_win32_ioutil_mkdir(filename, 0700) < 0 && errno != EEXIST) {
#endif
				* s = old;
				return FAILURE;
			}
			*s = old;
		}
		s++;
	}
	return SUCCESS;
}

static char* zend_file_cache_get_bin_file_path(zend_string * script_path)
{
	size_t len;
	char* filename;

#ifndef ZEND_WIN32
	len = strlen(ZCG(accel_directives).file_cache);
	filename = emalloc(len + 33 + ZSTR_LEN(script_path) + sizeof(SUFFIX));
	memcpy(filename, ZCG(accel_directives).file_cache, len);
	filename[len] = '/';
	memcpy(filename + len + 1, zend_system_id, 32);
	memcpy(filename + len + 33, ZSTR_VAL(script_path), ZSTR_LEN(script_path));
	memcpy(filename + len + 33 + ZSTR_LEN(script_path), SUFFIX, sizeof(SUFFIX));
#else
	len = strlen(ZCG(accel_directives).file_cache);

	filename = emalloc(len + 33 + 33 + ZSTR_LEN(script_path) + sizeof(SUFFIX));

	memcpy(filename, ZCG(accel_directives).file_cache, len);
	filename[len] = '\\';
	memcpy(filename + 1 + len, accel_uname_id, 32);
	len += 1 + 32;
	filename[len] = '\\';

	memcpy(filename + len + 1, zend_system_id, 32);

	if (ZSTR_LEN(script_path) >= 7 && ':' == ZSTR_VAL(script_path)[4] && '/' == ZSTR_VAL(script_path)[5] && '/' == ZSTR_VAL(script_path)[6]) {
		/* phar:// or file:// */
		*(filename + len + 33) = '\\';
		memcpy(filename + len + 34, ZSTR_VAL(script_path), 4);
		if (ZSTR_LEN(script_path) - 7 >= 2 && ':' == ZSTR_VAL(script_path)[8]) {
			*(filename + len + 38) = '\\';
			*(filename + len + 39) = ZSTR_VAL(script_path)[7];
			memcpy(filename + len + 40, ZSTR_VAL(script_path) + 9, ZSTR_LEN(script_path) - 9);
			memcpy(filename + len + 40 + ZSTR_LEN(script_path) - 9, SUFFIX, sizeof(SUFFIX));
		}
		else {
			memcpy(filename + len + 38, ZSTR_VAL(script_path) + 7, ZSTR_LEN(script_path) - 7);
			memcpy(filename + len + 38 + ZSTR_LEN(script_path) - 7, SUFFIX, sizeof(SUFFIX));
		}
	}
	else if (ZSTR_LEN(script_path) >= 2 && ':' == ZSTR_VAL(script_path)[1]) {
		/* local fs */
		*(filename + len + 33) = '\\';
		*(filename + len + 34) = ZSTR_VAL(script_path)[0];
		memcpy(filename + len + 35, ZSTR_VAL(script_path) + 2, ZSTR_LEN(script_path) - 2);
		memcpy(filename + len + 35 + ZSTR_LEN(script_path) - 2, SUFFIX, sizeof(SUFFIX));
	}
	else {
		/* network path */
		memcpy(filename + len + 33, ZSTR_VAL(script_path), ZSTR_LEN(script_path));
		memcpy(filename + len + 33 + ZSTR_LEN(script_path), SUFFIX, sizeof(SUFFIX));
	}
#endif

	return filename;
}

#pragma endregion zend_file_cache_mkdir

/**
 * Helper function for zend_file_cache_script_store().
 *
 * @return true on success, false on error and errno is set to indicate the cause of the error
 */
static bool zend_file_cache_script_write(int fd, const zend_persistent_script * script, const zend_file_cache_metainfo * info, const void* buf, const zend_string * s)
{
	ssize_t written;
	const ssize_t total_size = (ssize_t)(sizeof(*info) + script->size + info->str_size);

#ifdef HAVE_SYS_UIO_H
	const struct iovec vec[] = {
		{.iov_base = (void*)info, .iov_len = sizeof(*info) },
		{.iov_base = (void*)buf, .iov_len = script->size },
		{.iov_base = (void*)ZSTR_VAL(s), .iov_len = info->str_size },
	};

	written = writev(fd, vec, sizeof(vec) / sizeof(vec[0]));
	if (EXPECTED(written == total_size)) {
		return true;
	}

	errno = written == -1 ? errno : EAGAIN;
	return false;
#else
	if (UNEXPECTED(ZEND_LONG_MAX < (zend_long)total_size)) {
# ifdef EFBIG
		errno = EFBIG;
# else
		errno = ERANGE;
# endif
		return false;
	}

	written = write(fd, info, sizeof(*info));
	if (UNEXPECTED(written != sizeof(*info))) {
		errno = written == -1 ? errno : EAGAIN;
		return false;
	}

	written = write(fd, buf, script->size);
	if (UNEXPECTED(written != script->size)) {
		errno = written == -1 ? errno : EAGAIN;
		return false;
	}

	written = write(fd, ZSTR_VAL(s), info->str_size);
	if (UNEXPECTED(written != info->str_size)) {
		errno = written == -1 ? errno : EAGAIN;
		return false;
	}

	return true;
#endif
}

int zend_file_cache_script_store(zend_persistent_script * script, bool in_shm)
{
	int fd;
	char* filename;
	zend_file_cache_metainfo info;
	void* mem, * buf;

	filename = zend_file_cache_get_bin_file_path(script->script.filename);

	if (zend_file_cache_mkdir(filename, strlen(ZCG(accel_directives).file_cache)) != SUCCESS) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot create directory for file '%s', %s\n", filename, strerror(errno));
		efree(filename);
		return FAILURE;
	}

	fd = zend_file_cache_open(filename, O_CREAT | O_EXCL | O_RDWR | O_BINARY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		if (errno != EEXIST) {
			zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot create file '%s', %s\n", filename, strerror(errno));
		}
		efree(filename);
		return FAILURE;
	}

	if (zend_file_cache_flock(fd, LOCK_EX) != 0) {
		close(fd);
		efree(filename);
		return FAILURE;
	}

#if defined(__AVX__) || defined(__SSE2__)
	/* Align to 64-byte boundary */
	mem = emalloc(script->size + 64);
	buf = (void*)(((uintptr_t)mem + 63L) & ~63L);
#else
	mem = buf = emalloc(script->size);
#endif

	ZCG(mem) = zend_string_alloc(4096 - (_ZSTR_HEADER_SIZE + 1), 0);

	zend_shared_alloc_init_xlat_table();
	if (!in_shm) {
		script->corrupted = true; /* used to check if script restored to SHM or process memory */
	}
	zend_file_cache_serialize(script, &info, buf);
	if (!in_shm) {
		script->corrupted = false;
	}
	zend_shared_alloc_destroy_xlat_table();

	zend_string* const s = (zend_string*)ZCG(mem);

#if __has_feature(memory_sanitizer)
	/* The buffer may contain uninitialized regions. However, the uninitialized parts will not be
	 * used when reading the cache. We should probably still try to get things fully initialized
	 * for reproducibility, but for now ignore this issue. */
	__msan_unpoison(&info, sizeof(info));
	__msan_unpoison(buf, script->size);
#endif

	info.checksum = zend_adler32(ADLER32_INIT, buf, script->size);
	info.checksum = zend_adler32(info.checksum, (unsigned char*)ZSTR_VAL(s), info.str_size);

	if (!zend_file_cache_script_write(fd, script, &info, buf, s)) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot write to file '%s': %s\n", filename, strerror(errno));
		zend_string_release_ex(s, 0);
		close(fd);
		efree(mem);
		zend_file_cache_unlink(filename);
		efree(filename);
		return FAILURE;
	}

	zend_string_release_ex(s, 0);
	efree(mem);
	if (zend_file_cache_flock(fd, LOCK_UN) != 0) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot unlock file '%s': %s\n", filename, strerror(errno));
	}
	close(fd);
	efree(filename);

	return SUCCESS;
}

zend_persistent_script* zend_file_cache_script_load(zend_file_handle * file_handle)
{
	zend_string* full_path = file_handle->opened_path;
	int fd;
	char* filename;
	zend_persistent_script* script;
	zend_file_cache_metainfo info;
	// zend_accel_hash_entry *bucket;
	void* mem, * checkpoint, * buf;
	bool cache_it = true;
	unsigned int actual_checksum;
	bool ok;

	if (!full_path) {
		return NULL;
	}
	filename = zend_file_cache_get_bin_file_path(full_path);

	fd = zend_file_cache_open(filename, O_RDONLY | O_BINARY);
	if (fd < 0) {
		efree(filename);
		return NULL;
	}

	if (zend_file_cache_flock(fd, LOCK_SH) != 0) {
		close(fd);
		efree(filename);
		return NULL;
	}

	if (read(fd, &info, sizeof(info)) != sizeof(info)) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot read from file '%s' (info)\n", filename);
		zend_file_cache_flock(fd, LOCK_UN);
		close(fd);
		zend_file_cache_unlink(filename);
		efree(filename);
		return NULL;
	}

	/* verify header */
	if (memcmp(info.magic, "OPCACHE", 8) != 0) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot read from file '%s' (wrong header)\n", filename);
		zend_file_cache_flock(fd, LOCK_UN);
		close(fd);
		zend_file_cache_unlink(filename);
		efree(filename);
		return NULL;
	}
	if (memcmp(info.system_id, zend_system_id, 32) != 0) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot read from file '%s' (wrong \"system_id\")\n", filename);
		zend_file_cache_flock(fd, LOCK_UN);
		close(fd);
		zend_file_cache_unlink(filename);
		efree(filename);
		return NULL;
	}

	/* verify timestamp */
	if (ZCG(accel_directives).validate_timestamps &&
		zend_get_file_handle_timestamp(file_handle, NULL) != info.timestamp) {
		if (zend_file_cache_flock(fd, LOCK_UN) != 0) {
			zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot unlock file '%s'\n", filename);
		}
		close(fd);
		zend_file_cache_unlink(filename);
		efree(filename);
		return NULL;
	}

	checkpoint = zend_arena_checkpoint(CG(arena));
#if defined(__AVX__) || defined(__SSE2__)
	/* Align to 64-byte boundary */
	mem = zend_arena_alloc(&CG(arena), info.mem_size + info.str_size + 64);
	mem = (void*)(((uintptr_t)mem + 63L) & ~63L);
#else
	mem = zend_arena_alloc(&CG(arena), info.mem_size + info.str_size);
#endif

	if (read(fd, mem, info.mem_size + info.str_size) != (ssize_t)(info.mem_size + info.str_size)) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot read from file '%s' (mem)\n", filename);
		zend_file_cache_flock(fd, LOCK_UN);
		close(fd);
		zend_file_cache_unlink(filename);
		zend_arena_release(&CG(arena), checkpoint);
		efree(filename);
		return NULL;
	}
	if (zend_file_cache_flock(fd, LOCK_UN) != 0) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot unlock file '%s'\n", filename);
	}
	close(fd);

	/* verify checksum */
	if (ZCG(accel_directives).file_cache_consistency_checks &&
		(actual_checksum = zend_adler32(ADLER32_INIT, mem, info.mem_size + info.str_size)) != info.checksum) {
		zend_accel_error(ACCEL_LOG_WARNING, "corrupted file '%s' excepted checksum: 0x%08x actual checksum: 0x%08x\n", filename, info.checksum, actual_checksum);
		zend_file_cache_unlink(filename);
		zend_arena_release(&CG(arena), checkpoint);
		efree(filename);
		return NULL;
	}

use_process_mem:
	buf = mem;
	cache_it = false;

	ZCG(mem) = ((char*)mem + info.mem_size);
	script = (zend_persistent_script*)((char*)buf + info.script_offset);
	script->corrupted = !cache_it; /* used to check if script restored to SHM or process memory */

	ok = true;
	zend_try{
		zend_file_cache_unserialize(script, buf);
	} zend_catch{
		ok = false;
	} zend_end_try();
	if (!ok) {
		if (cache_it) {
			goto use_process_mem;
		}
		else {
			zend_arena_release(&CG(arena), checkpoint);
			efree(filename);
			return NULL;
		}
	}

	script->corrupted = false;

	if (cache_it) {
		// ZCSG(map_ptr_last) = CG(map_ptr_last);
		script->dynamic_members.last_used = ZCG(request_time);

		// zend_accel_hash_update(&ZCSG(hash), script->script.filename, 0, script);

		zend_accel_error(ACCEL_LOG_INFO, "File cached script loaded into memory '%s'", ZSTR_VAL(script->script.filename));

		zend_arena_release(&CG(arena), checkpoint);
	}
	efree(filename);

	return script;
}

void zend_file_cache_invalidate(zend_string* full_path)
{
	char* filename;

	filename = zend_file_cache_get_bin_file_path(full_path);

	zend_file_cache_unlink(filename);
	efree(filename);
}

#pragma region create_persistent_script

zend_persistent_script* create_persistent_script(void)
{
	zend_persistent_script* persistent_script = (zend_persistent_script*)emalloc(sizeof(zend_persistent_script));
	memset(persistent_script, 0, sizeof(zend_persistent_script));

	zend_hash_init(&persistent_script->script.function_table, 0, NULL, ZEND_FUNCTION_DTOR, 0);
	/* class_table is usually destroyed by free_persistent_script() that
	 * overrides destructor. ZEND_CLASS_DTOR may be used by standard
	 * PHP compiler
	 */
	zend_hash_init(&persistent_script->script.class_table, 0, NULL, ZEND_CLASS_DTOR, 0);

	return persistent_script;
}

static int zend_accel_get_auto_globals(void)
{
	int mask = 0;
	if (zend_hash_exists(&EG(symbol_table), ZSTR_KNOWN(ZEND_STR_AUTOGLOBAL_SERVER))) {
		mask |= ZEND_AUTOGLOBAL_MASK_SERVER;
	}
	if (zend_hash_exists(&EG(symbol_table), ZSTR_KNOWN(ZEND_STR_AUTOGLOBAL_ENV))) {
		mask |= ZEND_AUTOGLOBAL_MASK_ENV;
	}
	if (zend_hash_exists(&EG(symbol_table), ZSTR_KNOWN(ZEND_STR_AUTOGLOBAL_REQUEST))) {
		mask |= ZEND_AUTOGLOBAL_MASK_REQUEST;
	}
	return mask;
}

static void zend_accel_set_auto_globals(int mask)
{
	if (mask & ZEND_AUTOGLOBAL_MASK_SERVER) {
		zend_is_auto_global(ZSTR_KNOWN(ZEND_STR_AUTOGLOBAL_SERVER));
	}
	if (mask & ZEND_AUTOGLOBAL_MASK_ENV) {
		zend_is_auto_global(ZSTR_KNOWN(ZEND_STR_AUTOGLOBAL_ENV));
	}
	if (mask & ZEND_AUTOGLOBAL_MASK_REQUEST) {
		zend_is_auto_global(ZSTR_KNOWN(ZEND_STR_AUTOGLOBAL_REQUEST));
	}
	ZCG(auto_globals_mask) |= mask;
}

void zend_accel_finalize_delayed_early_binding_list(zend_persistent_script* persistent_script)
{
	if (!persistent_script->num_early_bindings) {
		return;
	}

	zend_early_binding* early_binding = persistent_script->early_bindings;
	zend_early_binding* early_binding_end = early_binding + persistent_script->num_early_bindings;
	zend_op_array* op_array = &persistent_script->script.main_op_array;
	zend_op* opline_end = op_array->opcodes + op_array->last;
	for (zend_op* opline = op_array->opcodes; opline < opline_end; opline++) {
		if (opline->opcode == ZEND_DECLARE_CLASS_DELAYED) {
			zend_string* rtd_key = Z_STR_P(RT_CONSTANT(opline, opline->op1) + 1);
			/* Skip early_binding entries that don't match, maybe their DECLARE_CLASS_DELAYED
			 * was optimized away. */
			while (!zend_string_equals(early_binding->rtd_key, rtd_key)) {
				early_binding++;
				if (early_binding >= early_binding_end) {
					return;
				}
			}

			early_binding->cache_slot = opline->extended_value;
			early_binding++;
			if (early_binding >= early_binding_end) {
				return;
			}
		}
	}
}

void zend_accel_move_user_functions(HashTable* src, uint32_t count, zend_script* script)
{
	Bucket* p, * end;
	HashTable* dst;
	zend_string* filename;
	dtor_func_t orig_dtor;
	zend_function* function;

	if (!count) {
		return;
	}

	dst = &script->function_table;
	filename = script->main_op_array.filename;
	orig_dtor = src->pDestructor;
	src->pDestructor = NULL;
	zend_hash_extend(dst, count, 0);
	end = src->arData + src->nNumUsed;
	p = end - count;
	for (; p != end; p++) {
		if (UNEXPECTED(Z_TYPE(p->val) == IS_UNDEF)) continue;
		function = Z_PTR(p->val);
		if (EXPECTED(function->type == ZEND_USER_FUNCTION)
			&& EXPECTED(function->op_array.filename == filename)) {
			_zend_hash_append_ptr(dst, p->key, function);
			zend_hash_del_bucket(src, p);
		}
	}
	src->pDestructor = orig_dtor;
}

void zend_accel_move_user_classes(HashTable* src, uint32_t count, zend_script* script)
{
	Bucket* p, * end;
	HashTable* dst;
	zend_string* filename;
	dtor_func_t orig_dtor;
	zend_class_entry* ce;

	if (!count) {
		return;
	}

	dst = &script->class_table;
	filename = script->main_op_array.filename;
	orig_dtor = src->pDestructor;
	src->pDestructor = NULL;
	zend_hash_extend(dst, count, 0);
	end = src->arData + src->nNumUsed;
	p = end - count;
	for (; p != end; p++) {
		if (UNEXPECTED(Z_TYPE(p->val) == IS_UNDEF)) continue;
		ce = Z_PTR(p->val);
		if (EXPECTED(ce->type == ZEND_USER_CLASS)
			&& EXPECTED(ce->info.user.filename == filename)) {
			_zend_hash_append_ptr(dst, p->key, ce);
			zend_hash_del_bucket(src, p);
		}
	}
	src->pDestructor = orig_dtor;
}

void zend_accel_free_delayed_early_binding_list(zend_persistent_script* persistent_script)
{
	if (persistent_script->num_early_bindings) {
		for (uint32_t i = 0; i < persistent_script->num_early_bindings; i++) {
			zend_early_binding* early_binding = &persistent_script->early_bindings[i];
			zend_string_release(early_binding->lcname);
			zend_string_release(early_binding->rtd_key);
			zend_string_release(early_binding->lc_parent_name);
		}
		efree(persistent_script->early_bindings);
		persistent_script->early_bindings = NULL;
		persistent_script->num_early_bindings = 0;
	}
}

void free_persistent_script(zend_persistent_script* persistent_script, int destroy_elements)
{
	if (!destroy_elements) {
		/* Both the keys and values have been transferred into the global tables.
		 * Set nNumUsed=0 to only deallocate the table, but not destroy any elements. */
		persistent_script->script.function_table.nNumUsed = 0;
		persistent_script->script.class_table.nNumUsed = 0;
	}
	else {
		destroy_op_array(&persistent_script->script.main_op_array);
	}

	zend_hash_destroy(&persistent_script->script.function_table);
	zend_hash_destroy(&persistent_script->script.class_table);

	if (persistent_script->script.filename) {
		zend_string_release_ex(persistent_script->script.filename, 0);
	}

	if (persistent_script->warnings) {
		for (uint32_t i = 0; i < persistent_script->num_warnings; i++) {
			zend_error_info* info = persistent_script->warnings[i];
			zend_string_release(info->filename);
			zend_string_release(info->message);
			efree(info);
		}
		efree(persistent_script->warnings);
	}

	zend_accel_free_delayed_early_binding_list(persistent_script);

	efree(persistent_script);
}

static zend_always_inline void _zend_accel_function_hash_copy(HashTable* target, HashTable* source, bool call_observers)
{
	zend_function* function1, * function2;
	Bucket* p, * end;
	zval* t;

	zend_hash_extend(target, target->nNumUsed + source->nNumUsed, 0);
	p = source->arData;
	end = p + source->nNumUsed;
	for (; p != end; p++) {
		ZEND_ASSERT(Z_TYPE(p->val) != IS_UNDEF);
		ZEND_ASSERT(p->key);
		t = zend_hash_find_known_hash(target, p->key);
		if (UNEXPECTED(t != NULL)) {
			goto failure;
		}
		_zend_hash_append_ptr_ex(target, p->key, Z_PTR(p->val), 1);
		if (UNEXPECTED(call_observers) && *ZSTR_VAL(p->key)) { // if not rtd key
			_zend_observer_function_declared_notify(Z_PTR(p->val), p->key);
		}
	}
	target->nInternalPointer = 0;

	return;

failure:
	function1 = Z_PTR(p->val);
	function2 = Z_PTR_P(t);
	CG(in_compilation) = 1;
	zend_set_compiled_filename(function1->op_array.filename);
	CG(zend_lineno) = function1->op_array.opcodes[0].lineno;
	if (function2->type == ZEND_USER_FUNCTION
		&& function2->op_array.last > 0) {
		zend_error(E_ERROR, "Cannot redeclare %s() (previously declared in %s:%d)",
			ZSTR_VAL(function1->common.function_name),
			ZSTR_VAL(function2->op_array.filename),
			(int)function2->op_array.opcodes[0].lineno);
	}
	else {
		zend_error(E_ERROR, "Cannot redeclare %s()", ZSTR_VAL(function1->common.function_name));
	}
}

static zend_always_inline void zend_accel_function_hash_copy(HashTable* target, HashTable* source)
{
	_zend_accel_function_hash_copy(target, source, 0);
}

static zend_never_inline void zend_accel_function_hash_copy_notify(HashTable* target, HashTable* source)
{
	_zend_accel_function_hash_copy(target, source, 1);
}

static zend_always_inline void _zend_accel_class_hash_copy(HashTable* target, HashTable* source, bool call_observers)
{
	Bucket* p, * end;
	zval* t;

	zend_hash_extend(target, target->nNumUsed + source->nNumUsed, 0);
	p = source->arData;
	end = p + source->nNumUsed;
	for (; p != end; p++) {
		ZEND_ASSERT(Z_TYPE(p->val) != IS_UNDEF);
		ZEND_ASSERT(p->key);
		t = zend_hash_find_known_hash(target, p->key);
		if (UNEXPECTED(t != NULL)) {
			if (EXPECTED(ZSTR_LEN(p->key) > 0) && EXPECTED(ZSTR_VAL(p->key)[0] == 0)) {
				/* Runtime definition key. There are two circumstances under which the key can
				 * already be defined:
				 *  1. The file has been re-included without being changed in the meantime. In
				 *     this case we can keep the old value, because we know that the definition
				 *     hasn't changed.
				 *  2. The file has been changed in the meantime, but the RTD key ends up colliding.
				 *     This would be a bug.
				 * As we can't distinguish these cases, we assume that it is 1. and keep the old
				 * value. */
				continue;
			}
			else if (UNEXPECTED(!ZCG(accel_directives).ignore_dups)) {
				zend_class_entry* ce1 = Z_PTR(p->val);
				if (!(ce1->ce_flags & ZEND_ACC_ANON_CLASS)) {
					CG(in_compilation) = 1;
					zend_set_compiled_filename(ce1->info.user.filename);
					CG(zend_lineno) = ce1->info.user.line_start;
					zend_error(E_ERROR,
						"Cannot declare %s %s, because the name is already in use",
						zend_get_object_type(ce1), ZSTR_VAL(ce1->name));
					return;
				}
				continue;
			}
		}
		else {
			zend_class_entry* ce = Z_PTR(p->val);
			_zend_hash_append_ptr_ex(target, p->key, Z_PTR(p->val), 1);
			if ((ce->ce_flags & ZEND_ACC_LINKED) && ZSTR_VAL(p->key)[0]) {
				if (ZSTR_HAS_CE_CACHE(ce->name)) {
					ZSTR_SET_CE_CACHE_EX(ce->name, ce, 0);
				}
				if (UNEXPECTED(call_observers)) {
					_zend_observer_class_linked_notify(ce, p->key);
				}
			}
		}
	}
	target->nInternalPointer = 0;
}

static zend_always_inline void zend_accel_class_hash_copy(HashTable* target, HashTable* source)
{
	_zend_accel_class_hash_copy(target, source, 0);
}

static zend_never_inline void zend_accel_class_hash_copy_notify(HashTable* target, HashTable* source)
{
	_zend_accel_class_hash_copy(target, source, 1);
}

void zend_accel_build_delayed_early_binding_list(zend_persistent_script* persistent_script)
{
	zend_op_array* op_array = &persistent_script->script.main_op_array;
	if (!(op_array->fn_flags & ZEND_ACC_EARLY_BINDING)) {
		return;
	}

	zend_op* end = op_array->opcodes + op_array->last;
	for (zend_op* opline = op_array->opcodes; opline < end; opline++) {
		if (opline->opcode == ZEND_DECLARE_CLASS_DELAYED) {
			persistent_script->num_early_bindings++;
		}
	}

	zend_early_binding* early_binding = persistent_script->early_bindings =
		emalloc(sizeof(zend_early_binding) * persistent_script->num_early_bindings);

	for (zend_op* opline = op_array->opcodes; opline < end; opline++) {
		if (opline->opcode == ZEND_DECLARE_CLASS_DELAYED) {
			zval* lcname = RT_CONSTANT(opline, opline->op1);
			early_binding->lcname = zend_string_copy(Z_STR_P(lcname));
			early_binding->rtd_key = zend_string_copy(Z_STR_P(lcname + 1));
			early_binding->lc_parent_name =
				zend_string_copy(Z_STR_P(RT_CONSTANT(opline, opline->op2)));
			early_binding->cache_slot = (uint32_t)-1;
			early_binding++;
		}
	}
}

static void zend_accel_do_delayed_early_binding(
	zend_persistent_script* persistent_script, zend_op_array* op_array)
{
	ZEND_ASSERT(!ZEND_MAP_PTR(op_array->run_time_cache));
	ZEND_ASSERT(op_array->fn_flags & ZEND_ACC_HEAP_RT_CACHE);
	void* run_time_cache = emalloc(op_array->cache_size);

	ZEND_MAP_PTR_INIT(op_array->run_time_cache, run_time_cache);
	memset(run_time_cache, 0, op_array->cache_size);

	zend_string* orig_compiled_filename = CG(compiled_filename);
	bool orig_in_compilation = CG(in_compilation);
	CG(compiled_filename) = persistent_script->script.filename;
	CG(in_compilation) = 1;
	for (uint32_t i = 0; i < persistent_script->num_early_bindings; i++) {
		zend_early_binding* early_binding = &persistent_script->early_bindings[i];
		zend_class_entry* ce = zend_hash_find_ex_ptr(EG(class_table), early_binding->lcname, 1);
		if (!ce) {
			zval* zv = zend_hash_find_known_hash(EG(class_table), early_binding->rtd_key);
			if (zv) {
				zend_class_entry* orig_ce = Z_CE_P(zv);
				zend_class_entry* parent_ce = !(orig_ce->ce_flags & ZEND_ACC_LINKED)
					? zend_hash_find_ex_ptr(EG(class_table), early_binding->lc_parent_name, 1)
					: NULL;
				if (parent_ce || (orig_ce->ce_flags & ZEND_ACC_LINKED)) {
					ce = zend_try_early_bind(orig_ce, parent_ce, early_binding->lcname, zv);
				}
			}
			if (ce && early_binding->cache_slot != (uint32_t)-1) {
				*(void**)((char*)run_time_cache + early_binding->cache_slot) = ce;
			}
		}
	}
	CG(compiled_filename) = orig_compiled_filename;
	CG(in_compilation) = orig_in_compilation;
}

#pragma endregion create_persistent_script

zend_op_array* zend_accel_load_script(zend_persistent_script* persistent_script, int from_shared_memory)
{
	zend_op_array* op_array;

	op_array = (zend_op_array*)emalloc(sizeof(zend_op_array));
	*op_array = persistent_script->script.main_op_array;

	if (EXPECTED(from_shared_memory)) {
		//if (ZCSG(map_ptr_last) > CG(map_ptr_last)) {
		//	zend_map_ptr_extend(ZCSG(map_ptr_last));
		//}

		/* Register __COMPILER_HALT_OFFSET__ constant */
		if (persistent_script->compiler_halt_offset != 0 &&
			persistent_script->script.filename) {
			zend_string* name;
			static const char haltoff[] = "__COMPILER_HALT_OFFSET__";

			name = zend_mangle_property_name(haltoff, sizeof(haltoff) - 1, ZSTR_VAL(persistent_script->script.filename), ZSTR_LEN(persistent_script->script.filename), 0);
			if (!zend_hash_exists(EG(zend_constants), name)) {
				zend_register_long_constant(ZSTR_VAL(name), ZSTR_LEN(name), persistent_script->compiler_halt_offset, 0, 0);
			}
			zend_string_release_ex(name, 0);
		}
	}

	if (zend_hash_num_elements(&persistent_script->script.function_table) > 0) {
		if (EXPECTED(!zend_observer_function_declared_observed)) {
			zend_accel_function_hash_copy(CG(function_table), &persistent_script->script.function_table);
		}
		else {
			zend_accel_function_hash_copy_notify(CG(function_table), &persistent_script->script.function_table);
		}
	}

	if (zend_hash_num_elements(&persistent_script->script.class_table) > 0) {
		if (EXPECTED(!zend_observer_class_linked_observed)) {
			zend_accel_class_hash_copy(CG(class_table), &persistent_script->script.class_table);
		}
		else {
			zend_accel_class_hash_copy_notify(CG(class_table), &persistent_script->script.class_table);
		}
	}

	if (persistent_script->num_early_bindings) {
		zend_accel_do_delayed_early_binding(persistent_script, op_array);
	}

	if (UNEXPECTED(!from_shared_memory)) {
		free_persistent_script(persistent_script, 0); /* free only hashes */
	}

	return op_array;
}

static zend_op_array* (*accelerator_orig_compile_file)(zend_file_handle* file_handle, int type);
static zend_class_entry* (*accelerator_orig_inheritance_cache_get)(zend_class_entry* ce, zend_class_entry* parent, zend_class_entry** traits_and_interfaces);
static zend_class_entry* (*accelerator_orig_inheritance_cache_add)(zend_class_entry* ce, zend_class_entry* proto, zend_class_entry* parent, zend_class_entry** traits_and_interfaces, HashTable* dependencies);
static zend_result(*accelerator_orig_zend_stream_open_function)(zend_file_handle* handle);
static zend_string* (*accelerator_orig_zend_resolve_path)(zend_string* filename);
static zif_handler orig_chdir = NULL;
static ZEND_INI_MH((*orig_include_path_on_modify)) = NULL;
static zend_result(*orig_post_startup_cb)(void);

static zend_persistent_script* store_script_in_file_cache(zend_persistent_script* new_persistent_script)
{
	uint32_t memory_used;

	zend_shared_alloc_init_xlat_table();

	/* Calculate the required memory size */
	memory_used = zend_accel_script_persist_calc(new_persistent_script, 0);

	/* Allocate memory block */
#if defined(__AVX__) || defined(__SSE2__)
	/* Align to 64-byte boundary */
	ZCG(mem) = zend_arena_alloc(&CG(arena), memory_used + 64);
	ZCG(mem) = (void*)(((uintptr_t)ZCG(mem) + 63L) & ~63L);
#elif ZEND_MM_NEED_EIGHT_BYTE_REALIGNMENT
	/* Align to 8-byte boundary */
	ZCG(mem) = zend_arena_alloc(&CG(arena), memory_used + 8);
	ZCG(mem) = (void*)(((uintptr_t)ZCG(mem) + 7L) & ~7L);
#else
	ZCG(mem) = zend_arena_alloc(&CG(arena), memory_used);
#endif

	zend_shared_alloc_clear_xlat_table();

	/* Copy into memory block */
	new_persistent_script = zend_accel_script_persist(new_persistent_script, 0);

	zend_shared_alloc_destroy_xlat_table();

	new_persistent_script->is_phar = is_phar_file(new_persistent_script->script.filename);

	/* Consistency check */
	if ((char*)new_persistent_script->mem + new_persistent_script->size != (char*)ZCG(mem)) {
		zend_accel_error(
			((char*)new_persistent_script->mem + new_persistent_script->size < (char*)ZCG(mem)) ? ACCEL_LOG_ERROR : ACCEL_LOG_WARNING,
			"Internal error: wrong size calculation: %s start=" ZEND_ADDR_FMT ", end=" ZEND_ADDR_FMT ", real=" ZEND_ADDR_FMT "\n",
			ZSTR_VAL(new_persistent_script->script.filename),
			(size_t)new_persistent_script->mem,
			(size_t)((char*)new_persistent_script->mem + new_persistent_script->size),
			(size_t)ZCG(mem));
	}

	zend_file_cache_script_store(new_persistent_script, /* is_shm */ false);

	return new_persistent_script;
}


static zend_persistent_script* cache_script_in_file_cache(zend_persistent_script* new_persistent_script, bool* from_shared_memory)
{
	uint32_t orig_compiler_options;

	orig_compiler_options = CG(compiler_options);
	CG(compiler_options) |= ZEND_COMPILE_WITH_FILE_CACHE;
	zend_optimize_script(&new_persistent_script->script, ZCG(accel_directives).optimization_level, ZCG(accel_directives).opt_debug_level);
	zend_accel_finalize_delayed_early_binding_list(new_persistent_script);
	CG(compiler_options) = orig_compiler_options;

	*from_shared_memory = true;
	return store_script_in_file_cache(new_persistent_script);
}


static zend_persistent_script* opcache_compile_file(zend_file_handle* file_handle, int type, zend_op_array** op_array_p)
{
	zend_persistent_script* new_persistent_script;
	uint32_t orig_functions_count, orig_class_count;
	zend_op_array* orig_active_op_array;
	zval orig_user_error_handler;
	zend_op_array* op_array;
	bool do_bailout = false;
	accel_time_t timestamp = 0;
	uint32_t orig_compiler_options = 0;

	/* Try to open file */
	if (file_handle->type == ZEND_HANDLE_FILENAME) {
		if (accelerator_orig_zend_stream_open_function(file_handle) != SUCCESS) {
			*op_array_p = NULL;
			if (!EG(exception)) {
				if (type == ZEND_REQUIRE) {
					zend_message_dispatcher(ZMSG_FAILED_REQUIRE_FOPEN, ZSTR_VAL(file_handle->filename));
				}
				else {
					zend_message_dispatcher(ZMSG_FAILED_INCLUDE_FOPEN, ZSTR_VAL(file_handle->filename));
				}
			}
			return NULL;
		}
	}

	/* check blacklist right after ensuring that file was opened */
	/* if (file_handle->opened_path && zend_accel_blacklist_is_blacklisted(&accel_blacklist, ZSTR_VAL(file_handle->opened_path), ZSTR_LEN(file_handle->opened_path))) {
		SHM_UNPROTECT();
		ZCSG(blacklist_misses)++;
		SHM_PROTECT();
		*op_array_p = accelerator_orig_compile_file(file_handle, type);
		return NULL;
	} */

	if (ZCG(accel_directives).validate_timestamps ||
		ZCG(accel_directives).file_update_protection ||
		ZCG(accel_directives).max_file_size > 0) {
		size_t size = 0;

		/* Obtain the file timestamps, *before* actually compiling them,
		 * otherwise we have a race-condition.
		 */
		timestamp = zend_get_file_handle_timestamp(file_handle, ZCG(accel_directives).max_file_size > 0 ? &size : NULL);

		/* If we can't obtain a timestamp (that means file is possibly socket)
		 *  we won't cache it
		 */
		if (timestamp == 0) {
			*op_array_p = accelerator_orig_compile_file(file_handle, type);
			return NULL;
		}

		/* check if file is too new (may be it's not written completely yet) */
		if (ZCG(accel_directives).file_update_protection &&
			((accel_time_t)(ZCG(request_time) - ZCG(accel_directives).file_update_protection) < timestamp)) {
			*op_array_p = accelerator_orig_compile_file(file_handle, type);
			return NULL;
		}

		if (ZCG(accel_directives).max_file_size > 0 && size > (size_t)ZCG(accel_directives).max_file_size) {
			SHM_UNPROTECT();
			// ZCSG(blacklist_misses)++;
			SHM_PROTECT();
			*op_array_p = accelerator_orig_compile_file(file_handle, type);
			return NULL;
		}
	}

	/* Save the original values for the op_array, function table and class table */
	orig_active_op_array = CG(active_op_array);
	orig_functions_count = EG(function_table)->nNumUsed;
	orig_class_count = EG(class_table)->nNumUsed;
	ZVAL_COPY_VALUE(&orig_user_error_handler, &EG(user_error_handler));

	/* Override them with ours */
	ZVAL_UNDEF(&EG(user_error_handler));
	if (ZCG(accel_directives).record_warnings) {
		zend_begin_record_errors();
	}

	zend_try{
		orig_compiler_options = CG(compiler_options);
		CG(compiler_options) |= ZEND_COMPILE_HANDLE_OP_ARRAY;
		CG(compiler_options) |= ZEND_COMPILE_IGNORE_INTERNAL_CLASSES;
		CG(compiler_options) |= ZEND_COMPILE_DELAYED_BINDING;
		CG(compiler_options) |= ZEND_COMPILE_NO_CONSTANT_SUBSTITUTION;
		CG(compiler_options) |= ZEND_COMPILE_IGNORE_OTHER_FILES;
		CG(compiler_options) |= ZEND_COMPILE_IGNORE_OBSERVER;
		if (ZCG(accel_directives).file_cache) {
			CG(compiler_options) |= ZEND_COMPILE_WITH_FILE_CACHE;
		}
		op_array = *op_array_p = accelerator_orig_compile_file(file_handle, type);
		CG(compiler_options) = orig_compiler_options;
	} zend_catch{
		op_array = NULL;
		do_bailout = true;
		CG(compiler_options) = orig_compiler_options;
	} zend_end_try();

	/* Restore originals */
	CG(active_op_array) = orig_active_op_array;
	EG(user_error_handler) = orig_user_error_handler;
	EG(record_errors) = 0;

	if (!op_array) {
		/* compilation failed */
		zend_free_recorded_errors();
		if (do_bailout) {
			zend_bailout();
		}
		return NULL;
	}

	/* Build the persistent_script structure.
	   Here we aren't sure we would store it, but we will need it
	   further anyway.
	*/
	new_persistent_script = create_persistent_script();
	new_persistent_script->script.main_op_array = *op_array;
	zend_accel_move_user_functions(CG(function_table), CG(function_table)->nNumUsed - orig_functions_count, &new_persistent_script->script);
	zend_accel_move_user_classes(CG(class_table), CG(class_table)->nNumUsed - orig_class_count, &new_persistent_script->script);
	zend_accel_build_delayed_early_binding_list(new_persistent_script);
	new_persistent_script->num_warnings = EG(num_errors);
	new_persistent_script->warnings = EG(errors);
	EG(num_errors) = 0;
	EG(errors) = NULL;

	efree(op_array); /* we have valid persistent_script, so it's safe to free op_array */

	/* Fill in the ping_auto_globals_mask for the new script. If jit for auto globals is enabled we
	   will have to ping the used auto global variables before execution */
	if (PG(auto_globals_jit)) {
		new_persistent_script->ping_auto_globals_mask = zend_accel_get_auto_globals();
	}

	if (ZCG(accel_directives).validate_timestamps) {
		/* Obtain the file timestamps, *before* actually compiling them,
		 * otherwise we have a race-condition.
		 */
		new_persistent_script->timestamp = timestamp;
		new_persistent_script->dynamic_members.revalidate = ZCG(request_time) + ZCG(accel_directives).revalidate_freq;
	}

	if (file_handle->opened_path) {
		new_persistent_script->script.filename = zend_string_copy(file_handle->opened_path);
	}
	else {
		new_persistent_script->script.filename = zend_string_copy(file_handle->filename);
	}
	zend_string_hash_val(new_persistent_script->script.filename);

	/* Now persistent_script structure is ready in process memory */
	return new_persistent_script;
}

zend_op_array* file_cache_compile_file(zend_file_handle* file_handle, int type)
{
	zend_persistent_script* persistent_script;
	zend_op_array* op_array = NULL;
	bool from_memory; /* if the script we've got is stored in SHM */

	if (php_is_stream_path(ZSTR_VAL(file_handle->filename)) &&
		!is_cacheable_stream_path(ZSTR_VAL(file_handle->filename))) {
		return accelerator_orig_compile_file(file_handle, type);
	}

	if (!file_handle->opened_path) {
		if (file_handle->type == ZEND_HANDLE_FILENAME &&
			accelerator_orig_zend_stream_open_function(file_handle) == FAILURE) {
			if (!EG(exception)) {
				if (type == ZEND_REQUIRE) {
					zend_message_dispatcher(ZMSG_FAILED_REQUIRE_FOPEN, ZSTR_VAL(file_handle->filename));
				}
				else {
					zend_message_dispatcher(ZMSG_FAILED_INCLUDE_FOPEN, ZSTR_VAL(file_handle->filename));
				}
			}
			return NULL;
		}
	}

	HANDLE_BLOCK_INTERRUPTIONS();
	SHM_UNPROTECT();
	persistent_script = zend_file_cache_script_load(file_handle);
	SHM_PROTECT();
	HANDLE_UNBLOCK_INTERRUPTIONS();
	if (persistent_script) {
		/* see bug #15471 (old BTS) */
		if (persistent_script->script.filename) {
			if (!EG(current_execute_data) || !EG(current_execute_data)->opline ||
				!EG(current_execute_data)->func ||
				!ZEND_USER_CODE(EG(current_execute_data)->func->common.type) ||
				EG(current_execute_data)->opline->opcode != ZEND_INCLUDE_OR_EVAL ||
				(EG(current_execute_data)->opline->extended_value != ZEND_INCLUDE_ONCE &&
					EG(current_execute_data)->opline->extended_value != ZEND_REQUIRE_ONCE)) {
				if (zend_hash_add_empty_element(&EG(included_files), persistent_script->script.filename) != NULL) {
					/* ext/phar has to load phar's metadata into memory */
					if (persistent_script->is_phar) {
						php_stream_statbuf ssb;
						char* fname = emalloc(sizeof("phar://") + ZSTR_LEN(persistent_script->script.filename));

						memcpy(fname, "phar://", sizeof("phar://") - 1);
						memcpy(fname + sizeof("phar://") - 1, ZSTR_VAL(persistent_script->script.filename), ZSTR_LEN(persistent_script->script.filename) + 1);
						php_stream_stat_path(fname, &ssb);
						efree(fname);
					}
				}
			}
		}
		replay_warnings(persistent_script->num_warnings, persistent_script->warnings);

		if (persistent_script->ping_auto_globals_mask & ~ZCG(auto_globals_mask)) {
			zend_accel_set_auto_globals(persistent_script->ping_auto_globals_mask & ~ZCG(auto_globals_mask));
		}

		return zend_accel_load_script(persistent_script, 1);
	}

	persistent_script = opcache_compile_file(file_handle, type, &op_array);

	if (persistent_script) {
		from_memory = false;
		persistent_script = cache_script_in_file_cache(persistent_script, &from_memory);
		return zend_accel_load_script(persistent_script, from_memory);
	}

	return op_array;
}


/* zend_compile() replacement */
zend_op_array* persistent_compile_file(zend_file_handle* file_handle, int type)
{
	if (!file_handle->filename || !ZCG(accelerator_enabled)) {
		/* The Accelerator is disabled, act as if without the Accelerator */
		ZCG(cache_opline) = NULL;
		ZCG(cache_persistent_script) = NULL;
		if (file_handle->filename
			&& ZCG(accel_directives).file_cache
			&& ZCG(enabled) && accel_startup_ok) {
			return file_cache_compile_file(file_handle, type);
		}
		return accelerator_orig_compile_file(file_handle, type);
	}
	else {
		ZCG(cache_opline) = NULL;
		ZCG(cache_persistent_script) = NULL;
		return file_cache_compile_file(file_handle, type);
	}
}


/* zend_stream_open_function() replacement for PHP 5.3 and above */
static zend_result persistent_stream_open_function(zend_file_handle* handle)
{
	if (ZCG(cache_persistent_script)) {
		/* check if callback is called from include_once or it's a main request */
		if ((!EG(current_execute_data) &&
			handle->primary_script &&
			ZCG(cache_opline) == NULL) ||
			(EG(current_execute_data) &&
				EG(current_execute_data)->func &&
				ZEND_USER_CODE(EG(current_execute_data)->func->common.type) &&
				ZCG(cache_opline) == EG(current_execute_data)->opline)) {

			/* we are in include_once or FastCGI request */
			handle->opened_path = zend_string_copy(ZCG(cache_persistent_script)->script.filename);
			return SUCCESS;
		}
		ZCG(cache_opline) = NULL;
		ZCG(cache_persistent_script) = NULL;
	}
	return accelerator_orig_zend_stream_open_function(handle);
}

/* zend_resolve_path() replacement for PHP 5.3 and above */
static zend_string* persistent_zend_resolve_path(zend_string* filename)
{
	ZCG(cache_opline) = NULL;
	ZCG(cache_persistent_script) = NULL;
	return accelerator_orig_zend_resolve_path(filename);
}

int persistent_startup(char* cache_id, char* file_cache) {
	accel_startup_ok = true;
	ZCG(accelerator_enabled) = true;
	ZCG(enabled) = true;

	ZCG(accel_directives).cache_id = cache_id;
	ZCG(accel_directives).file_cache = file_cache;
	ZCG(accel_directives).save_comments = true;
	ZCG(accel_directives).file_cache_only = true;
	ZCG(accel_directives).validate_timestamps = true;

	ZCG(accel_directives).optimization_level = 0x7FFEBFFF;
	ZCG(accel_directives).opt_debug_level = ZEND_DUMP_AFTER_PASS_7 | ZEND_DUMP_AFTER_PASS_9 | ZEND_DUMP_AFTER_PASS_11 | ZEND_DUMP_AFTER_PASS_13 | ZEND_DUMP_AFTER_OPTIMIZER;
	accel_post_startup();
	return 0;
}

static zend_result accel_post_startup(void)
{
#ifdef ZEND_WIN32
# if !defined(__has_feature) || !__has_feature(address_sanitizer)
	_setmaxstdio(2048); /* The default configuration is limited to 512 stdio files */
# endif
	accel_gen_uname_id();
#endif

	/* Override compiler */
	accelerator_orig_compile_file = zend_compile_file;
	zend_compile_file = persistent_compile_file;

	/* Override stream opener function (to eliminate open() call caused by
	 * include/require statements ) */
	accelerator_orig_zend_stream_open_function = zend_stream_open_function;
	zend_stream_open_function = persistent_stream_open_function;

	/* Override path resolver function (to eliminate stat() calls caused by
	 * include_once/require_once statements */
	accelerator_orig_zend_resolve_path = zend_resolve_path;
	zend_resolve_path = persistent_zend_resolve_path;

	ZCG(cwd) = NULL;
	ZCG(include_path) = NULL;

	accel_startup_ok = true;
	return SUCCESS;
}
