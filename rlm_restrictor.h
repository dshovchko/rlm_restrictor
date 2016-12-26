/*
 * rlm_restrictor.h
 *
 * Version:     $Id: rlm_restrictor.h,v 1.0 2016/08/30 10:45:32 shovchko Exp $
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  The FreeRADIUS server project
 * Copyright 2016  Dmitry Shovchko, <d.shovchko@gmail.com>
 *
 */

#ifndef _RLM_RESTRICTOR_H
#define _RLM_RESTRICTOR_H

#include <freeradius-devel/ident.h>
RCSIDH(rlm_restrictor_h, "$Id$")

#include        "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include        <pthread.h>
#include        <signal.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>
#include	<sys/socket.h>
#include	<netdb.h>
#include	<netinet/tcp.h>

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>

typedef uint8_t bool;
#define true 1
#define false 0

#define		RLMLOG	RADLOG_DIR"/rlm_restrictor.log"

/*
 *      Define a structure for rlm_restrictor configuration.
 *
 */
typedef struct rlm_restrictor_conf {
	uint32_t	auth_rate;
	uint32_t	ban_level;
	uint32_t	ban_duration;
	char		*log;
	int		disable_log;
	uint16_t	tid;
} rlm_restrictor_conf;

/*
 *      Define a structure for rlm_restrictor cache logins.
 *
 */
typedef struct cachel {
	char		*login;
	char		*password;
	time_t		lastauth;
	time_t		restrict;
	uint8_t		restrict_count;
	time_t		ban;
	struct cachel	*next;
} CACHEL;

int	restrictor_log(int , rlm_restrictor_conf *, const char *, ...);

CACHEL	*restrictor_cachelcreate(char *, char *);
void    restrictor_cachelbasicfree(CACHEL *);
void    restrictor_cachelfree(CACHEL **);
void    restrictor_cacheladd(CACHEL **, CACHEL *);

#endif /*_RLM_RESTRICTOR_H*/
