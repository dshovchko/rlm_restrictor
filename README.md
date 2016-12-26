# rlm_restrictor

Provides to flow restriction authorization blocked or incorrect users.
Too often authorization attempts will be blocked by the module for a short time. After several of these locks, the module will ban all attempts authorization "bad users" for a longer period.

Also, the module filters the accounting and discards all requests with unsupported acct-status-types.

Requirements:
============

1. FreeRADIUS >= 2.2.5

Installation
============

1. Download and unpack FreeRADIUS - e.g. to *freeradius/*
2. Put source code of this module in *freeradius/src/modules/rlm_restrictor/*
3. Add "rlm_restrictor" at the top of *freeradius/src/modules/stable* file
4. Change directory into *freeradius/src/modules/rlm_restrictor/*
5. Run *bootstrap* (you may need to install *autoconf* on your system)
6. Proceed with the standard FreeRADIUS installation procedure.
7. Verify if you have a file named *rlm_restrictor.so* in your libraries
   (usually /usr/lib or /usr/local/lib).

Usage:
=====

The modules configuration are under *raddb/modules/*. So, you should just create a file called restrictor with the configuration:

    restrictor {
            #
            # ANY RESTRICTION OR BAN TO INTERRUPT IN A STOPPPING ATTEMPT 
            # AUTHORIZATION AT THE TIME auth_rate SECONDS
            #
            #################################################################
            #
            # limit authorization requests, 1 for the specified number of seconds
            # (60 - default)
            #
            auth_rate = 60
            #
            # the number of pre-time limit on the authorization
            # duration auth_rate before it will impose the ban
            # (5 - default)
            #
            ban_level = 5
            #
            # ban duration in seconds
            # (3600 - default)
            #
            ban_duration = 3600
            #
            # log file name
            # ("${logdir}/rlm_restrictor.log" - default)
            #
            log = ${logdir}/rlm_restrictor.log
            #
            # disable logging
            # (no - default)
            #
            disable_log = no
    }

Then, put it in the authorize section at the beginning:

    authorize {
            restrictor
            
            # (... some other modules ...)
    }

And put it in the accounting section at the beginning:

    accounting {
            restrictor
            
            # (... some other modules ...)
    }
