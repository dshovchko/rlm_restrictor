/*
 * rlm_restrictor.c
 *
 * Version:	$Id: 8b804f4d061af672fac87c3e2cfca1da93b6d8b7 $
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2016  Dmitry Shovchko <d.shovchko@gmail.com>
 *
 * Aug 2016,  Dmitry Shovchko <d.shovchko@gmail.com>
 *	- Initial release 2.00
 *
 * Sep 2016,  Dmitry Shovchko <d.shovchko@gmail.com>
 *	- Change restrict algorithm
 *	- Add ban mode
 *	- Release version 2.01
 *
 * Dec 2016,  Dmitry Shovchko <d.shovchko@gmail.com>
 *	- Add disable_log options
 *	- Release version 2.02
 *
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include	"config.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<time.h>

#include	"rlm_restrictor.h"

static pthread_mutex_t	c_lock;
static pthread_mutex_t	check_lock;

static uint16_t		rlm_restrictor_counter = 0;
static CACHEL		*cachels = NULL;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "auth_rate", PW_TYPE_INTEGER,
		offsetof(rlm_restrictor_conf, auth_rate), NULL, "60" },
	{ "ban_level", PW_TYPE_INTEGER,
		offsetof(rlm_restrictor_conf, ban_level), NULL, "5" },
	{ "ban_duration", PW_TYPE_INTEGER,
		offsetof(rlm_restrictor_conf, ban_duration), NULL, "3600" },
	{ "log", PW_TYPE_STRING_PTR,
		offsetof(rlm_restrictor_conf, log), NULL, RLMLOG },
	{ "disable_log", PW_TYPE_BOOLEAN,
		offsetof(rlm_restrictor_conf, disable_log), NULL, "no" },
	
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int rlm_restrictor_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_restrictor_conf	*p;

	/*
         *	Set up a storage area for instance data
         */
        p = rad_malloc(sizeof(*p));
        if (!p) {
                return -1;
        }
        memset(p, 0, sizeof(*p));

	/*
         *	If the configuration parameters can't be parsed, then
         *	fail.
         */
        if (cf_section_parse(conf, p, module_config) < 0) {
                free(p);
                return -1;
        }
	
	restrictor_log(L_INFO, p, "Instantiate module (version %s / release %s)", MVERSION, MRELEASE);
	
	p->tid = 0;
	
	pthread_mutex_init(&c_lock, NULL);
	pthread_mutex_init(&check_lock, NULL);
	
	*instance = p;
	
	restrictor_log(L_INFO, p, "Instantiate module ok");

	return 0;
}

/*
 *	Authorize
 */
static int rlm_restrictor_authorize(void *instance, REQUEST *request)
{
	rlm_restrictor_conf		cbuf;
	rlm_restrictor_conf		*data = &cbuf;
	CACHEL				*rec, *last, *next;
	time_t				diff;
	char				ipsrc[INET6_ADDRSTRLEN];

	/*
         *      They MUST have a User-Name attribute
         */
        if ((request->username == NULL) ||
            (request->username->length == 0)) {
		
		radius_xlat(ipsrc, sizeof(ipsrc), "%{%{Packet-Src-IP-Address}:-%{Packet-Src-IPv6-Address}}", request, NULL);
                radlog(L_ERR, "rlm_restrictor: attribute \"User-Name\" not present or zero length [nas %s]", ipsrc);
                return RLM_MODULE_INVALID;
        }
	/*
         *      They MUST have a User-Password attribute
         */
	if (!request->password ||
            (request->password->attribute != PW_PASSWORD)) {
		
		radius_xlat(ipsrc, sizeof(ipsrc), "%{%{Packet-Src-IP-Address}:-%{Packet-Src-IPv6-Address}}", request, NULL);
                radlog(L_ERR, "rlm_restrictor: request that does not contain a User-Password attribute [nas %s]", ipsrc);
                return RLM_MODULE_INVALID;
        }
        if (request->password->length == 0) {
		
		radius_xlat(ipsrc, sizeof(ipsrc), "%{%{Packet-Src-IP-Address}:-%{Packet-Src-IPv6-Address}}", request, NULL);
                radlog(L_ERR, "rlm_restrictor: attribute User-Password is zero length [nas %s]", ipsrc);
                return RLM_MODULE_INVALID;
        }
	
	memcpy(&cbuf, instance, sizeof(rlm_restrictor_conf));
	
	pthread_mutex_lock(&c_lock);
	rlm_restrictor_counter++;
	data->tid = rlm_restrictor_counter;
	pthread_mutex_unlock(&c_lock);
	
	pthread_mutex_lock(&check_lock);
	
	rec = cachels;
	last = NULL;
	while (rec != NULL) {
		// calc time from last auth
		diff = time(NULL) - rec->lastauth;
		
		// check it
		if (diff > data->auth_rate) {
			// expired
			restrictor_log(L_INFO, data, "reset %s/%s", rec->login, rec->password);
			
			next = rec->next;
                        if (last == NULL) {
                                // first in list
                                cachels = next;
                        }
                        else {
                                last->next = next;
                        }
			restrictor_cachelbasicfree(rec);
                        rec = next;
			
			continue;
		}
		
		if ((strcmp(rec->login, request->username->vp_strvalue) == 0) &&
		    (strcmp(rec->password, request->password->vp_strvalue) == 0)) {
			
			/*	matched login
			 *			OVERLIMIT!!!
			 */
			
			// update record last auth tstamp
			rec->lastauth = time(NULL);
			
			if (rec->ban != 0) {
				// login banned
				
				// check the expiration time ban
				if (rec->lastauth > rec->ban) {
					// ban expired
					restrictor_log(L_AUTH, data, "reset ban %s/%s", rec->login, rec->password);
					
					rec->ban = 0;
					rec->restrict = 0;
					
					// reset restrictor counter
					rec->restrict_count = 1;
					
					pthread_mutex_unlock(&check_lock);
					
					return RLM_MODULE_OK;
				}
				else {
					// ban not expired
					restrictor_log(L_AUTH, data, "ban %s/%s: (%d/%d)", rec->login, rec->password, diff, (rec->ban - rec->lastauth));
				}
			}
			else if (rec->restrict != 0){
				// login restricted
				
				// check the expiration time restrict
				if (rec->lastauth > rec->restrict) {
					// restrict expired
					restrictor_log(L_AUTH, data, "reset restrict %s/%s", rec->login, rec->password);
					
					rec->ban = 0;
					rec->restrict = 0;
					
					pthread_mutex_unlock(&check_lock);
					
					return RLM_MODULE_OK;
				}
				else {
					// restrict not expired
					restrictor_log(L_AUTH, data, "restrict %s/%s: (%d/%d)", rec->login, rec->password, diff, (rec->restrict - rec->lastauth));
				}
			}
			else {
				// login not restricted and not banned
				
				// check penalty level
				if (rec->restrict_count > data->ban_level) {
					// set the expire time ban
					rec->ban = rec->lastauth + data->ban_duration;
					restrictor_log(L_AUTH, data, "set ban %s/%s: (%d/%d)", rec->login, rec->password, diff, rec->restrict_count);
				}
				else {
					// set the expire time restrict
					rec->restrict = rec->lastauth + data->auth_rate;
					restrictor_log(L_AUTH, data, "set restrict %s/%s: (%d/%d)", rec->login, rec->password, diff, rec->restrict_count);
					// increase restrictor counter
					rec->restrict_count++;
				}
			}
			
			pthread_mutex_unlock(&check_lock);
			
			return RLM_MODULE_USERLOCK;
		}
		// go to next record
		last = rec;
                rec = rec->next;
	}
	
	/*
	 *	add login/password to cachel
	 */
	rec = restrictor_cachelcreate(request->username->vp_strvalue, request->password->vp_strvalue);
	restrictor_cacheladd(&cachels, rec);
	rec = NULL;
	restrictor_log(L_INFO, data, "add: %s/%s", request->username->vp_strvalue, request->password->vp_strvalue);
	
	pthread_mutex_unlock(&check_lock);
	
	return RLM_MODULE_OK;
}

/*
 *	Accounting
 */
static int rlm_restrictor_acct(void *instance, REQUEST *request)
{
	VALUE_PAIR			*pair;
	int				acctstatustype = 0;
	rlm_restrictor_conf		cbuf;
	rlm_restrictor_conf		*data = &cbuf;
	char				ipsrc[INET6_ADDRSTRLEN];
	
	/*
         * Find the Acct Status Type
         */
        if ((pair = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE)) != NULL)
                acctstatustype = pair->lvalue;
        else
        {
                radius_xlat(ipsrc, sizeof(ipsrc), "%{%{Packet-Src-IP-Address}:-%{Packet-Src-IPv6-Address}}", request, NULL);
		radlog(L_ERR, "rlm_restrictor: packet has no account status type. [nas %s]", ipsrc);
                return RLM_MODULE_INVALID;
        }
	
	memcpy(&cbuf, instance, sizeof(rlm_restrictor_conf));
	
	pthread_mutex_lock(&c_lock);
	rlm_restrictor_counter++;
	data->tid = rlm_restrictor_counter;
	pthread_mutex_unlock(&c_lock);
        
        /*
         *  Check unsupported acct-status-types
         */
        switch (acctstatustype)
        {
                case PW_STATUS_START:
                case PW_STATUS_ALIVE:
                case PW_STATUS_STOP:
		case PW_STATUS_ACCOUNTING_ON:
		case PW_STATUS_ACCOUNTING_OFF:
                        break;
                default:
                        restrictor_log(L_ACCT, data, "reject type=%d", acctstatustype);
			
                        return RLM_MODULE_REJECT;
                        break;
        }
	
	return RLM_MODULE_OK;
}

/*
 *	Only free memory we allocated.
 */
static int rlm_restrictor_detach(void *instance)
{
	rlm_restrictor_conf		*data = (rlm_restrictor_conf *)instance;

	radlog(L_DBG, "Detach module RESTRICTOR");
	
	/*
	 *	Flush logins cache
	 */
	restrictor_cachelfree(&cachels);
	
	free(data->log);
	
	pthread_mutex_destroy(&check_lock);
	pthread_mutex_destroy(&c_lock);
	
	free(instance);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_restrictor = {
	RLM_MODULE_INIT,
	"restrictor",
	RLM_TYPE_THREAD_SAFE,		/* type */
	rlm_restrictor_instantiate,	/* instantiation */
	rlm_restrictor_detach,		/* detach */
	{
		NULL,			/* authentication */
		rlm_restrictor_authorize,	/* authorization */
		rlm_restrictor_acct,	/* preaccounting */
		rlm_restrictor_acct,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
