/*
 * cachelogin.c
 *
 * Version:	$Id: cachelogin.c,v 1.0 2016/08/30 16:08:02 shovchko Exp $
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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <freeradius-devel/radiusd.h>
#include "rlm_restrictor.h"

/*
 *      Create a new cachel record.
 */
CACHEL *restrictor_cachelcreate(char *login, char *password)
{
	CACHEL		*rec;

	rec = rad_malloc(sizeof(CACHEL));
        memset(rec, 0, sizeof(CACHEL));

	rec->login = strdup(login);
	rec->password = strdup(password);
	rec->lastauth = time(NULL);
	rec->restrict = 0;
	rec->restrict_count = 1;
	rec->ban = 0;
	rec->next = NULL;

	return rec;
}

/*
 *      release the memory used by a single cachel record
 *      just a wrapper around free() for now.
 */
void    restrictor_cachelbasicfree(CACHEL *rec)
{
	free(rec->login);
	free(rec->password);
	
	/* clear the memory here */
	memset(rec, 0, sizeof(*rec));
        free(rec);
}

/*
 *      Release the memory used by a list of cachel records,
 *      and sets the cachel pointer to NULL.
 */
void    restrictor_cachelfree(CACHEL **rec_ptr)
{
	CACHEL	*next, *rec;

	if (!rec_ptr) return;
	rec = *rec_ptr;
	
	while (rec != NULL) {
		next = rec->next;
		restrictor_cachelbasicfree(rec);
		rec = next;
	}

	*rec_ptr = NULL;
}

/*
 *      Add a cacheid at the end of a CACHEL list.
 */
void    restrictor_cacheladd(CACHEL **first, CACHEL *add)
{
	CACHEL *i;

        if (*first == NULL) {
                *first = add;
                return;
        }
	
        for(i = *first; i->next; i = i->next) ;

        i->next = add;
}
