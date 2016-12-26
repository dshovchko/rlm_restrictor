/*
 * log.c
 *
 * Version:     $Id: log.c,v 1.3 2007/02/26 19:04:32 shovchko Exp $
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
 * Copyright 2007  Dmitry Shovchko, <d.shovchko@gmail.com>
 *
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "config.h"

#include <stdio.h>

#include <freeradius-devel/radiusd.h>
#include "rlm_restrictor.h"

/*
 *      Logging facility names
 */
static const FR_NAME_NUMBER levels[] = {
        { ": Debug: ",		L_DBG   },
        { ": Auth: ",		L_AUTH  },
        { ": Proxy: ",		L_PROXY },
        { ": Info: ",		L_INFO  },
        { ": Acct: ",		L_ACCT  },
        { ": Error: ",		L_ERR   },
        { NULL, 0 }
};

int restrictor_vlog(int lvl, rlm_restrictor_conf *conf, const char *fmt, va_list ap)
{
        FILE		*logfile = NULL;
	unsigned char	*p;
        char		buffer[8192];
	const char	*s;
        int		len;
        time_t		timeval;

        if (!conf->log) return -1;

        if ((logfile = fopen(conf->log, "a")) == (FILE *) NULL)
	{
                radlog(L_ERR, "rlm_restrictor: Couldn't open file %s",
                       conf->log);
		return -1;
	}

        timeval = time(NULL);
        CTIME_R(&timeval, buffer, 8192);

	len = strlen(buffer);
	snprintf(buffer + len, sizeof(buffer) - len - 1, "%05d", conf->tid);

	s = fr_int2str(levels, (lvl & ~L_CONS), ": ");
        strcat(buffer, s);

        len = strlen(buffer);
        vsnprintf(buffer + len, sizeof(buffer) - len - 1, fmt, ap);

        /*
         *      Filter out characters not in Latin-1.
         */
        for (p = (unsigned char *)buffer; *p != '\0'; p++) {
                if (*p == '\r' || *p == '\n')
                        *p = ' ';
                else if (*p < 32 || (*p >= 128 && *p <= 160))
                        *p = '?';
        }
        strcat(buffer, "\n");

        int fd = fileno(logfile);

        rad_lockfd(fd, 4096);
        fputs(buffer, logfile);
        fclose(logfile); /* and release the lock */

	return 0;
}

int restrictor_log(int lvl, rlm_restrictor_conf *conf, const char *msg, ...)
{
        va_list		ap;
        int		r = 0;

        if (!conf->disable_log) {
                va_start(ap, msg);
                r = restrictor_vlog(lvl, conf, msg, ap);
                va_end(ap);
        }

        return r;
}
