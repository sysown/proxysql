/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Required system headers
 */

#include <usual/base.h>
#include <usual/ctype.h>

#include <sys/stat.h>

#include <stdarg.h>
#include <limits.h>

#include <usual/tls/tls.h>

#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

/*
 * libc compat functions.
 */

//#ifndef HAVE_LSTAT
//static inline int lstat(const char *path, struct stat *st)
//{
//	return stat(path, st);
//}
//#endif

//bool check_unix_peer_name(int fd, const char *username);

//void change_user(const char *user);

//void change_file_mode(const char *fn, mode_t mode, const char *user, const char *group);
