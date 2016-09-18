

/* asprintf and getopt_long */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>


#include <net-snmp/net-snmp-config.h>
#include <string.h>
#include <sys/time.h>
#include <regex.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>

/* getenv */
#include <stdlib.h>


/* getopt_long */
#include <getopt.h>

#include "cisco_interfaces.h"
#include "utils.h"

/* uptime counter */
unsigned int uptime = 0, sleep_usecs = 0;
unsigned int lastcheck = 0, deltachecks = 0;
long double ifdeltachecks =0;
unsigned long global_timeout = DFLT_TIMEOUT;

int
main(int argc, char *argv[])
{
    int     opt;
    int     get_aliases_flag = 0;
    int     match_aliases_flag = 0;
    int     crit_on_down_flag = 1;
    int     get_names_flag = 0;
    int     in_err_tolerance = 50;
    int     out_err_tolerance = -1;
    unsigned int    trimalias = 0;
    int     bw = 0;
    u64     speed = 0;
    char    *hostname=0, *community=0, *list=0, *exclude_list=0, *list_down=0, *oldperfdatap=0, *ifname=0;
    char    *user=0, *auth_proto=0, *auth_pass=0, *priv_proto=0, *priv_pass=0;


    int     status, index, countif, lastif, ifNumber, regex_down_flag;
    int     i, j, k;
    int     errorflag = 0;
    int     warnflag = 0;
    double  inload = 0,outload = 0;
    size_t  size;

    struct  timeval tv;
    struct  timezone tz;
    long double starttime;

    netsnmp_session session, *ss;
    netsnmp_pdu    *pdu, *response;
    netsnmp_variable_list *vars;

    struct ifStruct interfaces[MAX_INTERFACES]; /* current interface data */
    struct ifStruct oldperfdata[MAX_INTERFACES]; /* previous check interface data */

    /* zero the interfaces array */
    memset(interfaces, '\0', sizeof (interfaces));
    memset(oldperfdata, '\0', sizeof (oldperfdata));

    char outstr[MAX_STRING];
    memset(outstr, 0, sizeof(outstr));
    String out;
    out.max = MAX_STRING;
    out.len = 0;
    out.text = outstr;

    char *progname = strrchr(argv[0], '/');
    if (*progname && *(progname+1))
        progname++;
    else
        progname = "check_interfaces";

    /* parse options */
    static struct option longopts[] =
    {
        {"aliases",       no_argument,        NULL,   'a'},
        {"match-aliases", no_argument,        NULL,   'A'},
        {"bandwidth",     required_argument,  NULL,   'b'},
        {"community",     required_argument,  NULL,   'c'},
        {"down-is-ok",    no_argument,        NULL,   'd'},
        {"regex-down",    required_argument,  NULL,   'D'},
        {"errors",        required_argument,  NULL,   'e'},
        {"out-errors",    required_argument,  NULL,   'f'},
        {"hostname",      required_argument,  NULL,   'h'},
        {"auth-proto",    required_argument,  NULL,   'j'},
        {"auth-phrase",   required_argument,  NULL,   'J'},
        {"priv-proto",    required_argument,  NULL,   'k'},
        {"priv-phrase",   required_argument,  NULL,   'K'},
        {"perfdata",      required_argument,  NULL,   'p'},
        {"regex",         required_argument,  NULL,   'r'},
        {"exclude-regex", required_argument,  NULL,   'R'},
        {"if-names",      no_argument,        NULL,   'N'},
        {"speed",         required_argument,  NULL,   's'},
        {"lastcheck",     required_argument,  NULL,   't'},
        {"user",          required_argument,  NULL,   'u'},
        {"trim",          required_argument,  NULL,   'x'},
        {"help",          no_argument,        NULL,   '?'},
        {"timeout",       required_argument,  NULL,     2},
        {"sleep",         required_argument,  NULL,     3},
        {NULL,            0,                  NULL,     0}
    };

    while ((opt = getopt_long(argc, argv, "aAb:c:dD:e:f:h:j:J:k:K:Np:r:R:s:t:u:x:?", longopts, NULL)) != -1)
    {
        switch(opt)
        {
            case 'a':
                get_aliases_flag = 1;
                break;
            case 'A':
                match_aliases_flag = 1;
                break;
            case 'b':
                bw = strtol(optarg, NULL, 10);
                break;
            case 'c':
                community = optarg;
                break;
            case 'd':
                crit_on_down_flag = 0;
                break;
            case 'D':
                list_down = optarg;
            case 'e':
                in_err_tolerance = strtol(optarg, NULL, 10);
                break;
            case 'f':
                out_err_tolerance = strtol(optarg, NULL, 10);
                break;
            case 'h':
                hostname = optarg;
                break;
            case 'j':
                auth_proto = optarg;
                break;
            case 'J':
                auth_pass = optarg;
                break;
            case 'k':
                priv_proto = optarg;
                break;
            case 'K':
                priv_pass = optarg;
                break;
            case 'N':
                get_names_flag = 1;
                break;
            case 'p':
                if (strlen(optarg) >1)
                    oldperfdatap = optarg;
                break;
            case 'r':
                list = optarg;
                break;
            case 'R':
                exclude_list = optarg;
                break;
            case 's':
                speed = strtoull(optarg, NULL, 10);
                break;
            case 't':
                lastcheck = strtol(optarg, NULL, 10);
                break;
            case 'u':
                user = optarg;
                break;
            case 'x':
                trimalias = strtol(optarg, NULL, 10);
                break;
            case 2:
                /* convert from ms to us */
                global_timeout = strtoul(optarg, NULL, 10) * 1000UL;
                break;
            case 3:
                /* convert from ms to us */
                sleep_usecs = strtoul(optarg, NULL, 10) * 1000UL;
                break;
            case '?':
            default:
                exit(usage(progname));

        }
    }
    argc -= optind;
    argv += optind;

    if (!(hostname))
        exit(usage(progname));

    /* get the start time */
    gettimeofday(&tv, &tz);
    starttime=(long double)tv.tv_sec + (((long double)tv.tv_usec)/1000000);

    if (exclude_list && !list)
        /* use .* as the default regex */
        list = ".*";

    /* parse the interfaces regex */
    regex_t regex, exclude_regex;
    if (list) {
        status = regcomp(&regex, list, REG_ICASE|REG_EXTENDED|REG_NOSUB);
        if (status != 0) {
            printf("Error creating regex\n");
            exit (3);
        }

        if (exclude_list) {
            status = regcomp(&exclude_regex, exclude_list, REG_ICASE|REG_EXTENDED|REG_NOSUB);
            if (status != 0) {
                printf("Error creating exclusion regex\n");
                exit (3);
            }
        }
    }

    /* set the MIB variable if it is unset to avoid net-snmp warnings */
    if (getenv("MIBS") == NULL)
        setenv("MIBS", "", 1);

   if (!community)
        community = default_community;

    if (user)
        /* use snmpv3 */
        ss=start_session_v3(&session, user, auth_proto, auth_pass, priv_proto, priv_pass, hostname);
    else
        ss=start_session(&session, community, hostname);

    size = (sizeof(oid_if) / sizeof(char *)) - 1;
    /* allocate the space for the interface OIDs */
    struct OIDStruct lastOID[4], *OIDp;
    OIDp = (struct OIDStruct *) calloc(size, sizeof(struct OIDStruct));

    /* get the number of interfaces, and their index numbers
     *
     * We will attempt to get all the interfaces in a single packet
     * - which should manage about 64 interfaces.
     * If the end interface has not been reached, we fetch more packets - this is
     * necessary to work around buggy switches that lie about the ifNumber
     */

    lastif = countif = index = ifNumber =0;

    while (lastif==0) {

        /* get the ifNumber and as many interfaces as possible */
        pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
        pdu->max_repetitions = MAX_INTERFACES;

        if (countif==0)
        {
            pdu->non_repeaters = NON_REPEATERS;
            for (i = 0; oid_if[i]; i++) {
                parseoids(i, oid_if[i], OIDp);
                snmp_add_null_var(pdu, OIDp[i].name, OIDp[i].name_len);
            }
        }
        else {
            /* we have not received all interfaces in the preceding packet, so fetch the next lot */
            pdu->non_repeaters = 0;
            for (i = 0; i <OID_REPEATERS ; i++, index++) {
                index &= OID_REPEATERS-1;
                snmp_add_null_var(pdu, lastOID[index].name, lastOID[index].name_len);
            }
        }

        /* send the request */
        status = snmp_synch_response(ss, pdu, &response);
        if (sleep_usecs) usleep(sleep_usecs);

        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {

            vars = response->variables;

            if (countif==0) {
                /* assuming that the uptime and ifNumber come first */

                while (!ifNumber) {
                    if (!(memcmp(OIDp[0].name, vars->name, OIDp[0].name_len * sizeof(oid)))) {
                        /* uptime */
                        if (vars->type == ASN_TIMETICKS)
                            /* uptime is in 10ms units -> convert to seconds */
                            uptime = *(vars->val.integer) / 100;
                    } else if (!memcmp(OIDp[1].name, vars->name, OIDp[1].name_len * sizeof(oid))) {
                        /* we received a valid IfNumber */
                        ifNumber = *(vars->val.integer);
                        if (ifNumber == 0) {
                            /* there are no interfaces! Stop here */
                            printf("No interfaces found");
                            exit (0);
                        }
                    } else {
#ifdef DEBUG
                        printf("no IfNumber parameter, assuming 64 interfaces\n");
#endif
                        ifNumber = 64;
                    }

                    vars = vars->next_variable;
                }

                if (ifNumber > MAX_INTERFACES) {
                    /* if MAX_INTERFACES is not enough then we need to recompile */
                    printf("Error, this device has more than %d interfaces - you will need to alter the code and recompile, sorry.\n", MAX_INTERFACES);
                    exit (3);
                }

#ifdef DEBUG
                fprintf(stderr, "got %d interfaces\n", ifNumber);
#endif
            } else {
                /* subsequent replies have no ifNumber */
            }

            #ifdef DEBUG
                fprintf(stderr, "interface (%d of %d)\n", (countif+1), ifNumber);
            #endif
            for (vars = vars; vars; vars = vars->next_variable) {
                #ifdef DEBUG
                    print_variable(vars->name, vars->name_length, vars);
                #endif
                /*
                 * if the next OID is shorter
                 * or if the next OID doesn't begin with our base OID
                 * then we have reached the end of the table :-)
                 * print_variable(vars->name, vars->name_length, vars);
                 */

                k = -1;
                /* compare the received value to the requested value */
                for ( i = 2; oid_if[i]; i++) {
                    if (!memcmp(OIDp[i].name, vars->name, OIDp[i].name_len*sizeof(oid))) {
                        k = i;
                        break;
                    }
                }
                if (k== -1) {
                    #ifdef DEBUG
                        fprintf(stderr, "reached end of interfaces\n");
                    #endif
                    lastif++;
                    countif--;
                    break;
                }

                switch(k) /* the offset into oid_vals */
                {
                    case 2: /* ifDescr */
                         /* now we fill our interfaces array with the index number and
                         * the description that we have received
                         */
                        if (vars->type == ASN_OCTET_STR) {
                            interfaces[countif].index = (int) vars->name[(vars->name_length - 1)];
                            MEMCPY(interfaces[countif].descr, vars->val.string, vars->val_len);
                            if (list && !get_names_flag && !match_aliases_flag && !match_regexs(&regex, (exclude_list ? &exclude_regex :0), interfaces[countif].descr))
                                interfaces[countif].ignore =1;
                        }
                        break;
                    case 3: /* ifName */
                        if (vars->type == ASN_OCTET_STR)
                            MEMCPY(interfaces[countif].name, vars->val.string, vars->val_len);
                            if (list && get_names_flag && !match_aliases_flag && !match_regexs(&regex, (exclude_list ? &exclude_regex :0), interfaces[countif].name))
                                interfaces[countif].ignore =1;
                        break;
                    case 4: /* ifAlias */
                        if (vars->type == ASN_OCTET_STR)
                            MEMCPY(interfaces[countif].alias, vars->val.string, vars->val_len);
                            if (list && match_aliases_flag && !match_regexs(&regex, (exclude_list ? &exclude_regex :0), interfaces[countif].alias))
                                interfaces[countif].ignore =1;
                            if (trimalias && trimalias < vars->val_len) {
                                MEMCPY(interfaces[countif].alias, (vars->val.string)+trimalias, vars->val_len - trimalias);
                                TERMSTR(interfaces[countif].alias, vars->val_len - trimalias);
                            }
                        break;
                    case 5: /* ifType */
                        if (vars->type == ASN_INTEGER)
                            interfaces[countif].type = *(vars->val.integer);
                        countif++;
                        break;
                }

                /* save the OID in case we need additional packets */
                index &=OID_REPEATERS-1;
                memcpy(lastOID[index].name, vars->name, (vars->name_length  * sizeof(oid)));
                lastOID[index++].name_len = vars->name_length;
            }

            if (countif < ifNumber) {
                if (lastif)
                {
#ifdef DEBUG
                    fprintf(stderr, "Device says it has %d but really has %d interfaces\n", ifNumber, countif);
#endif
                    ifNumber = countif;
                } else {
#ifdef DEBUG
                    fprintf(stderr, "Sending another packet\n");
#endif
                }
            } else {
                lastif++;
                if (countif > ifNumber) {
#ifdef DEBUG
                    fprintf(stderr, "Device says it has %d but really has %d interfaces\n", ifNumber, countif);
#endif
                    ifNumber = countif;
                }
#ifdef DEBUG
                fprintf(stderr, "%d interfaces found\n", ifNumber);
#endif
            }

        } else {
            /*
             * FAILURE: print what went wrong!
             */

            if (status == STAT_SUCCESS)
                printf("Error in packet\nReason: %s\n",
                        snmp_errstring(response->errstat));
            else if (status == STAT_TIMEOUT) {
                gettimeofday(&tv, &tz);
                printf("Timeout while reading interface descriptions from %s (starttime=%.2Lf, exittime=%.2Lf, timeout=%lu, ifNumber=%d)\n", ss->peername, starttime, ((long double)tv.tv_sec + (((long double)tv.tv_usec)/1000000)), global_timeout, ifNumber);
                exit(EXITCODE_TIMEOUT);
            }
            else
                snmp_sess_perror("snmp_bulkget", ss);
            exit (2);

        }
        /*
         * Clean up:
         *   free the response.
         */
        if (response) {
            snmp_free_pdu(response);
            response = 0;
        }
    }

    if (list)
        regfree(&regex);
    if (exclude_list)
        regfree(&exclude_regex);

    if (OIDp) {
        free(OIDp);
        OIDp = 0;
    }


    /*
    *   Retrieve the interface values
    */
    size = (sizeof(oid_vals) / sizeof(char *)) - 1;
    /* allocate the space for the OIDs */
    OIDp = (struct OIDStruct *) calloc(size, sizeof(struct OIDStruct));

    /* here we are retrieving single values, not walking the table */

    for (i = 0; i < ifNumber; i++) {

         if (!interfaces[i].ignore) {

            pdu = snmp_pdu_create(SNMP_MSG_GET);
            #ifdef DEBUG
                fprintf(stderr, "%s\n", interfaces[i].descr);
            #endif
            for (j = 0; oid_vals[j]; j++) {
                parseoids(j, oid_vals[j], OIDp);
                OIDp[j].name[OIDp[j].name_len++] = interfaces[i].index;
                snmp_add_null_var(pdu, OIDp[j].name, OIDp[j].name_len);
            }
            pdu->non_repeaters = j;
            pdu->max_repetitions = 0;

            status = snmp_synch_response(ss, pdu, &response);

            if (sleep_usecs) usleep(sleep_usecs);

            gettimeofday(&tv, &tz);

            if (status == STAT_SUCCESS && (response->errstat == SNMP_ERR_NOERROR || response->errstat == SNMP_ERR_NOSUCHNAME))
            {
                /* add the interface to the oldperfdata list */
                if (interfaces[i].descr) strcpy(oldperfdata[i].descr, interfaces[i].descr);
                if (interfaces[i].name)  strcpy(oldperfdata[i].name,  interfaces[i].name);

                interfaces[i].checktime = (long double)tv.tv_sec + (((long double)tv.tv_usec)/1000000);

                for (vars = response->variables; vars; vars = vars->next_variable) {

                    k = -1;
                    /* compare the received value to the requested value */
                    for ( j = 0; oid_vals[j]; j++) {
                        if (!memcmp(OIDp[j].name, vars->name, OIDp[j].name_len*sizeof(oid))) {
                            k = j;
                            break;
                        }
                    }

                    switch(k) /* the offset into oid_vals */
                    {
                        case 0: /* ifAdminStatus */
                            if (vars->type == ASN_INTEGER && *(vars->val.integer)==2) {
                                interfaces[i].admin_down= 1;
                            }
                            break;
                        case 1: /*ifOperStatus */
                            if (vars->type == ASN_INTEGER)
                                /* 1 is up(OK), 5 is dormant(assume OK) */
                                interfaces[i].status = (*(vars->val.integer)==1 || *(vars->val.integer)==5)?1:0;
                            break;
                        case 2: /* ifHCInOctets */
                            if (vars->type == ASN_COUNTER64)
                                 interfaces[i].inOctets = convertto64((vars->val.counter64), 0);
                            break;
                        case 3: /* ifHCInUcastPkts */
                            if (vars->type == ASN_COUNTER64)
                                 interfaces[i].inUcastPkts = convertto64((vars->val.counter64), 0);
                            break;
                        case 4: /* ifHCInMulticastPkts */
                            if (vars->type == ASN_COUNTER64)
                                 interfaces[i].inMulticastPkts = convertto64((vars->val.counter64), 0);
                            break;
                        case 5: /* ifHCInBroadcastPkts */
                            if (vars->type == ASN_COUNTER64)
                                 interfaces[i].inBroadcastPkts = convertto64((vars->val.counter64), 0);
                            break;
                        case 6: /* ifInDiscards */
                            if (vars->type == ASN_COUNTER)
                                interfaces[i].inDiscards = *(vars->val.integer);
                            break;
                        case 7: /* ifInErrors */
                            if (vars->type == ASN_COUNTER || vars->type == ASN_INTEGER)
                                interfaces[i].inErrors = *(vars->val.integer);
                            break;
                        case 8: /* locIfInCRC */
                            if (vars->type == ASN_COUNTER || vars->type == ASN_INTEGER)
                                interfaces[i].inCRC = *(vars->val.integer);
                            break;
                        case 9: /* ifHCOutOctets */
                            if (vars->type == ASN_COUNTER64)
                                 interfaces[i].outOctets = convertto64((vars->val.counter64), 0);
                            break;
                        case 10: /* ifHCOutUcastPkts */
                            if (vars->type == ASN_COUNTER64)
                                 interfaces[i].outUcastPkts = convertto64((vars->val.counter64), 0);
                            break;
                        case 11: /* ifHCOutMulticastPkts */
                            if (vars->type == ASN_COUNTER64)
                                 interfaces[i].outMulticastPkts = convertto64((vars->val.counter64), 0);
                            break;
                        case 12: /* ifHCOutBroadcastPkts */
                            if (vars->type == ASN_COUNTER64)
                                 interfaces[i].outBroadcastPkts = convertto64((vars->val.counter64), 0);
                            break;
                        case 13: /* ifOutDiscards */
                            if (vars->type == ASN_COUNTER)
                                interfaces[i].outDiscards = *(vars->val.integer);
                            break;
                        case 14: /* ifOutErrors */
                            if (vars->type == ASN_COUNTER || vars->type == ASN_INTEGER)
                                interfaces[i].outErrors = *(vars->val.integer);
                            break;
                        case 15: /* ifSpeed */
                            /* don't overwrite a high-speed value */
                            if (vars->type == ASN_GAUGE && !(interfaces[i].speed))
                                interfaces[i].speed = *(vars->val.integer);
                            break;
                        case 16: /* ifHighSpeed */
                            if (vars->type == ASN_GAUGE)
                                /* convert to bits / sec */
                                interfaces[i].speed = ((u64)*(vars->val.integer)) * 1000000ULL;
                            break;
                    }
                }
            } else {
                /*
                * FAILURE: print what went wrong!
                */

                if (status == STAT_SUCCESS)
                    printf("Error in packet\nReason: %s\n",
                    snmp_errstring(response->errstat));
                else if (status == STAT_TIMEOUT)
                {
                    printf("Timeout fetching interface stats from %s (starttime=%.2Lf, exittime=%.2Lf, timeout=%lu, ifDescr=%s)\n", ss->peername, starttime, ((long double)tv.tv_sec + (((long double)tv.tv_usec)/1000000)), global_timeout, (interfaces[i].descr ? interfaces[i].descr : ""));
                    exit(EXITCODE_TIMEOUT);
                }
                else {
                    printf("other error\n");
                    snmp_sess_perror("snmp_bulkget", ss);
                }
                exit(2);
            }
            /*
             * Clean up:
             *   free the response.
             */
            if (response) {
                snmp_free_pdu(response);
                response = 0;
            }
        }
    }

    if (OIDp) {
        free(OIDp);
        OIDp = 0;
    }

    snmp_close(ss);

    gettimeofday(&tv, &tz);

    if (lastcheck) deltachecks=((long double)tv.tv_sec + (((long double)tv.tv_usec)/1000000) - lastcheck);

    /* do not use old perfdata if the device has been reset recently
     * Note that a switch will typically rollover the uptime counter every 497 days
     * which is infrequent enough to not bother about :-)
     * UPTIME_TOLERANCE_IN_SECS doesn't need to be a big number
     */
    if ((deltachecks + UPTIME_TOLERANCE_IN_SECS) > uptime)
        deltachecks = 0;

    if (oldperfdatap && deltachecks && oldperfdatap[0])
        parse_perfdata(oldperfdatap, oldperfdata, ifNumber);

    /* parse the interfaces regex */
    regex_t regex_down;
    if (list_down) {
        status = regcomp(&regex_down, list_down, REG_ICASE|REG_EXTENDED|REG_NOSUB);
        if (status != 0) {
            printf("Error creating regex for down interfaces\n");
            exit (3);
        }
    }

    countif =0;
    for (i=0; i<ifNumber; i++)  {
        if (interfaces[i].descr && !interfaces[i].ignore) {

            ifname = get_names_flag ? interfaces[i].name : interfaces[i].descr;
            /* interface is DOWN */
            if (!interfaces[i].status) {
                if (crit_on_down_flag) {
                    regex_down_flag =0;
                    if (list_down) {
                        if ((!get_names_flag && !match_aliases_flag && match_regexs(&regex_down, 0, interfaces[i].descr)) || (get_names_flag && !match_aliases_flag && match_regexs(&regex_down, 0, interfaces[i].name)) || (get_names_flag && match_aliases_flag && match_regexs(&regex_down, 0, interfaces[i].alias)))
                           regex_down_flag =1;
                    }


                    if (!list_down || regex_down_flag) {
                        addstr(&out, "%s", ifname);
                        if (get_aliases_flag)
                            addstr(&out, " (%s)", interfaces[i].alias);
                        addstr(&out, " is %s, ", interfaces[i].admin_down ? "admin down" : "down");

                        errorflag++;
                    }
                }
                interfaces[i].ignore =1;
                continue;
            }
            /* check if errors on the interface are increasing faster than our defined value */
            if (oldperfdatap && oldperfdata[i].inErrors && oldperfdata[i].outErrors &&
                (interfaces[i].inErrors > (oldperfdata[i].inErrors + (unsigned long) in_err_tolerance)
                || interfaces[i].outErrors > (oldperfdata[i].outErrors + (unsigned long) out_err_tolerance))) {

                addstr(&out, "%s", ifname);
                if (get_aliases_flag)
                    addstr(&out, " (%s)", interfaces[i].alias);
                addstr(&out, " has ");
                if (interfaces[i].inErrors  > (oldperfdata[i].inErrors + (unsigned long) in_err_tolerance))
                    addstr(&out, "+%lu in ", interfaces[i].inErrors - oldperfdata[i].inErrors);
                if (interfaces[i].outErrors > (oldperfdata[i].outErrors + (unsigned long) out_err_tolerance))
                    addstr(&out, "+%lu out ", interfaces[i].outErrors - oldperfdata[i].outErrors);
                addstr(&out, "errors, ");

                warnflag++;
            }
            if (deltachecks && oldperfdatap){
                ifdeltachecks = interfaces[i].checktime - oldperfdata[i].checktime;
                interfaces[i].inBitps = (subtract64(interfaces[i].inOctets, oldperfdata[i].inOctets) / (u64)ifdeltachecks) * 8ULL;
                interfaces[i].outBitps = (subtract64(interfaces[i].outOctets, oldperfdata[i].outOctets) / (u64)ifdeltachecks) * 8ULL;
                if (bw >0) {
                    if (speed) {
                        inload = (long double)interfaces[i].inBitps / ((long double)speed/100L);
                        outload = (long double)interfaces[i].outBitps / ((long double)speed/100L);
                    } else {
                        /* use the interface speed if a speed is not given */
                        inload = (long double)interfaces[i].inBitps / ((long double)interfaces[i].speed/100L);
                        outload = (long double)interfaces[i].outBitps / ((long double)interfaces[i].speed/100L);
                    }
                    if ((int)inload > bw || (int)outload > bw)
                        warnflag++;
                }
            }
            countif++;
        }
    }
    if (list_down)
        regfree(&regex_down);


    addstr (&out, " got %d interfaces", countif);


    if (errorflag)
        printf("CRITICAL: ");
    else if (warnflag)
        printf("WARNING: ");
    else
        printf("OK: ");

    /* calculate time taken, print perfdata */
    gettimeofday(&tv, &tz);

    printf("%*s | interfaces::starttime=%.2Lf exectime=%.2Lf", (int)out.len, out.text, starttime, (((long double)tv.tv_sec + ((long double)tv.tv_usec/1000000)) - starttime ));
    if (uptime)
        printf(" uptime=%us", uptime);
    if (deltachecks)
        printf(" deltachecks=%us", deltachecks);


    for (i=0; i<ifNumber; i++)  {
        if (interfaces[i].descr && !interfaces[i].ignore) {
            ifname = get_names_flag ? interfaces[i].name : interfaces[i].descr;
            printf(" %s::checktime=%.2Lf", ifname, interfaces[i].checktime);
            if (get_aliases_flag)
                printf(" alias=%s", interfaces[i].alias);

            if (deltachecks && oldperfdatap) {
                printf(" inBitps=%llub", interfaces[i].inBitps);
                printf(" outBitps=%llub", interfaces[i].outBitps);
            }

            printf(" inOctets=%llu", interfaces[i].inOctets);
            printf(" inUcastPkts=%llu", interfaces[i].inUcastPkts);
            printf(" inMulticastPkts=%llu", interfaces[i].inMulticastPkts);
            printf(" inBroadcastPkts=%llu", interfaces[i].inBroadcastPkts);
            printf(" inDiscards=%lu", interfaces[i].inDiscards);
            printf(" inErrors=%lu", interfaces[i].inErrors);
            printf(" inCRC=%lu", interfaces[i].inCRC);
            printf(" outOctets=%llu", interfaces[i].outOctets);
            printf(" outUcastPkts=%llu", interfaces[i].outUcastPkts);
            printf(" outMulticastPkts=%llu", interfaces[i].outMulticastPkts);
            printf(" outBroadcastPkts=%llu", interfaces[i].outBroadcastPkts);
            printf(" outDiscards=%lu", interfaces[i].outDiscards);
            printf(" outErrors=%lu", interfaces[i].outErrors);
        }
    }

    printf("\n");

    SOCK_CLEANUP;
    return ((errorflag)?2:((warnflag)?1:0));
}

/*
 * tokenize a string containing performance data and fill a struct with
 * the individual variables
 */
int parse_perfdata(char *oldperfdatap, struct ifStruct *oldperfdata, int ifNumber)
{
    char *last=0, *last2, *word, *ifname=0, *ifname2=0, *varstr, *valstr, *ptr;
    int index =-1;
    /* first split at spaces */
    for (word = strtok_r(oldperfdatap, " ", &last); word; word = strtok_r(NULL, " ", &last)) {
        if (strstr(word, "interfaces::"))
            continue;

        /* split the ifname::var=value*/
        ptr = strchr(word, ':');
        if ( ptr && ( ptr < strchr(word, '='))) {
            ifname = strtok_r(word, ":", &last2);
            varstr = strtok_r(ptr+2, "=", &last2);
            valstr = last2;
            #ifdef DEBUG
                fprintf(stderr, "ifname=%s, varstr=%s, valstr=%s\n", ifname, varstr, valstr);
            #endif
            if (ifname && varstr && valstr) {
                if (!ifname2 || strcmp(ifname,ifname2)) {
                    ifname2 = ifname;
                    index =-1;
                    for (int i=0; i < ifNumber; i++) {
                        if (!strcmp(oldperfdata[i].descr, ifname2) || !strcmp(oldperfdata[i].name, ifname2)) {
                            index =i;
                            break;
                        }
                    }
                }
                if (index >=0){
                    if (!strcmp(varstr, "checktime")) {
                        oldperfdata[index].checktime = strtold(valstr, NULL);
                    }
                    else if (!strcmp(varstr, "alias")) {
                        strcpy(oldperfdata[index].alias, valstr);
                    }
                    else if (!strcmp(varstr, "inOctets")) {
                        oldperfdata[index].inOctets = strtoull(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "inUcastPkts")) {
                        oldperfdata[index].inUcastPkts = strtoull(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "inMulticastPkts")) {
                        oldperfdata[index].inMulticastPkts = strtoull(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "inBroadcastPkts")) {
                        oldperfdata[index].inBroadcastPkts = strtoull(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "inDiscards")) {
                        oldperfdata[index].inDiscards = strtoul(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "inErrors")) {
                        oldperfdata[index].inErrors = strtoul(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "inCRC")) {
                        oldperfdata[index].inCRC = strtoull(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "outOctets")) {
                        oldperfdata[index].outOctets = strtoull(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "outUcastPkts")) {
                        oldperfdata[index].outUcastPkts = strtoull(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "outMulticastPkts")) {
                        oldperfdata[index].outMulticastPkts = strtoull(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "outBroadcastPkts")) {
                        oldperfdata[index].outBroadcastPkts = strtoull(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "outDiscards")) {
                        oldperfdata[index].outDiscards = strtoul(valstr, NULL,10);
                    }
                    else if (!strcmp(varstr, "outErrors")) {
                        oldperfdata[index].outErrors = strtoul(valstr, NULL,10);
                    }
                }
            }
        }
    }

    return (0);
}


int usage(char *progname)
{
    printf("Usage: %s -h <hostname> [OPTIONS]\n", progname);

    printf(" -c|--community\t\tcommunity (default public)\n");
    printf(" -r|--regex\t\tinterface list regexp\n");
    printf(" -R|--exclude-regex\tinterface list negative regexp\n");
    printf(" -e|--errors\t\tnumber of in errors to consider a warning (default 50)\n");
    printf(" -f|--out-errors\tnumber of out errors to consider a warning (default same as in errors)\n");
    printf(" -p|--perfdata\t\tlast check perfdata\n");
    printf(" -t|--lastcheck\t\tlast checktime (unixtime)\n");
    printf(" -b|--bandwidth\t\tbandwidth warn level in %%\n");
    printf(" -s|--speed\t\toverride speed detection with this value (bits per sec)\n");
    printf(" -j|--auth-proto\tSNMPv3 Auth Protocol (SHA|MD5)\n");
    printf(" -J|--auth-phrase\tSNMPv3 Auth Phrase\n");
    printf(" -k|--priv-proto\tSNMPv3 Privacy Protocol (AES|DES)\n");
    printf(" -K|--priv-phrase\tSNMPv3 Privacy Phrase\n");
    printf(" -u|--user\t\tSNMPv3 User\n");
    printf(" -d|--down-is-ok\tdisables critical alerts for down interfaces\n");
    printf(" -D|--regex for down interfaces\t interface list regexp for down interfaces\n");
    printf(" -a|--aliases\t\tretrieves the interface description\n");
    printf(" -x|--trim\t\tcut this number of characters from the start of interface aliases\n");
    printf(" -A|--match-aliases\talso match against aliases\n");
    printf(" -N|--if-names\t\tuse ifName instead of ifDescr\n");
    printf("    --timeout\t\tsets the SNMP timeout (in ms)\n");
    printf("    --sleep\t\tsleep between every SNMP query (in ms)\n");
    printf("\n");
    return 3;
}

netsnmp_session *start_session_v3(netsnmp_session *session, char *user, char *auth_proto, char *auth_pass, char *priv_proto, char *priv_pass, char *hostname)
{
    netsnmp_session *ss;

    init_snmp("snmp_bulkget");

    snmp_sess_init(session);
    session->peername = hostname;

    session->version = SNMP_VERSION_3;

    session->securityName = user;
    session->securityModel = SNMP_SEC_MODEL_USM;
    session->securityNameLen = strlen(user);


    if (priv_proto && priv_pass) {
        if (!strcmp(priv_proto, "AES")) {
            session->securityPrivProto = snmp_duplicate_objid(usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN);
            session->securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
        } else if (!strcmp(priv_proto, "DES")) {
            session->securityPrivProto = snmp_duplicate_objid(usmDESPrivProtocol, USM_PRIV_PROTO_DES_LEN);
            session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
        } else {
            printf("Unknown priv protocol %s\n", priv_proto);
            exit(3);
        }
        session->securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
        session->securityPrivKeyLen = USM_PRIV_KU_LEN;
    } else {
        session->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
        session->securityPrivKeyLen = 0;
    }


    if (auth_proto && auth_pass) {
        if (!strcmp(auth_proto, "SHA")) {
            session->securityAuthProto = snmp_duplicate_objid(usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN);
            session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
        } else if (!strcmp(auth_proto, "MD5")) {
            session->securityAuthProto = snmp_duplicate_objid(usmHMACMD5AuthProtocol, USM_AUTH_PROTO_MD5_LEN);
            session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
        } else {
            printf("Unknown auth protocol %s\n", auth_proto);
            exit(3);
        }
        session->securityAuthKeyLen = USM_AUTH_KU_LEN;
    } else {
        session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
        session->securityAuthKeyLen = 0;
        session->securityPrivKeyLen = 0;
    }

    if ((session->securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) || (session->securityLevel == SNMP_SEC_LEVEL_AUTHNOPRIV)) {
        if(generate_Ku(session->securityAuthProto, session->securityAuthProtoLen, (unsigned char *)auth_pass, strlen(auth_pass),
                    session->securityAuthKey, &session->securityAuthKeyLen) != SNMPERR_SUCCESS)
            printf("Error generating AUTH sess\n");
        if (session->securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) {
            if (generate_Ku(session->securityAuthProto, session->securityAuthProtoLen, (unsigned char *)priv_pass, strlen(priv_pass),
                        session->securityPrivKey, &session->securityPrivKeyLen) != SNMPERR_SUCCESS)
                printf("Error generating PRIV sess\n");
        }
    }

    session->timeout = global_timeout;
    session->retries = 3;

    /*
     * Open the session
     */
    SOCK_STARTUP;
    ss = snmp_open(session);    /* establish the session */

    if (!ss) {
        snmp_sess_perror("snmp_bulkget", session);
        SOCK_CLEANUP;
        exit(1);
    }

    return(ss);

}

netsnmp_session *start_session(netsnmp_session *session, char *community, char *hostname)
{
    netsnmp_session *ss;

    /*
     * Initialize the SNMP library
     */
    init_snmp("snmp_bulkget");

    /* setup session to hostname */
    snmp_sess_init(session);
    session->peername = hostname;
    session->version = SNMP_VERSION_2c;
    session->community = (u_char *)community;
    session->community_len = strlen(community);
    session->timeout = global_timeout;
    session->retries = 3;

    /*
     * Open the session
     */
    SOCK_STARTUP;
    ss = snmp_open(session);    /* establish the session */

    if (!ss) {
        snmp_sess_perror("snmp_bulkget", session);
        SOCK_CLEANUP;
        exit(1);
    }

    return(ss);
}

int parseoids(int i, char *oid_list, struct OIDStruct *query)
{
    /* parse oid list
     *
     * read each OID from our array and add it to the pdu request
     */

    query[i].name_len = MAX_OID_LEN;
    if (!snmp_parse_oid(oid_list, query[i].name, &query[i].name_len)) {
        snmp_perror(oid_list);
        SOCK_CLEANUP;
        exit(1);
    }
    return(0);
}

int match_regexs(const regex_t *re, const regex_t *exre, const char *to_match)
{
    int status, status2 =0;
    status = !regexec(re, to_match, (size_t) 0, NULL, 0);

    if (status && exre)
        status2 = !regexec(exre, to_match, (size_t) 0, NULL, 0);

    return (status && !status2);
}


u64 convertto64(struct counter64 *val64, unsigned long *val32)
{
    u64 temp64;

    if ((isZeroU64(val64)))
    {
        if (val32)
            temp64 = (u64)(*val32);
        else
            temp64 = 0;
    }
    else
        temp64 = ((u64)(val64->high) << 32) + val64->low;

    return (temp64);
}

u64 subtract64(u64 big64, u64 small64)
{
    if (big64 < small64) {
        /* either the device was reset or the counter overflowed
         */
        if ((deltachecks + UPTIME_TOLERANCE_IN_SECS) > uptime)
            /* the device was reset, or the uptime counter rolled over
             * so play safe and return 0 */
            return 0;
        else {
            /* we assume there was exactly 1 counter rollover
             * - of course there may have been more than 1 if it
             * is a 32 bit counter ...
             */
            if (small64 > OFLO32)
                return (OFLO64 - small64 + big64);
            else
                return (OFLO32 - small64 + big64);
        }
    } else
        return (big64 - small64);
}
