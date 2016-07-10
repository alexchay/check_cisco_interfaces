

#ifdef HAVE_GETADDRINFO
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif /* HAVE_GETADDRINFO */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

/*
 * defines
 * MAX_INTERFACES = allocate memory for this number of interfaces
 * MAX_STRING = allocate memory for this length of output string
 */
/*#define MAX_INTERFACES 64 */
#define MAX_INTERFACES 1024
#define MAX_STRING 65536
#define MAX_DESCR_LEN 60
#define UPTIME_TOLERANCE_IN_SECS 30
#define OFLO32 4294967295ULL
#define OFLO64 18446744073709551615ULL

/* default SNMP community */
static char default_community[] = "public";

/* default timeout is 15s */
#define DFLT_TIMEOUT 15000000UL

/* should a timeout return critical(2) or unknown(3)? */
#define EXITCODE_TIMEOUT 3

#define MEMCPY(a, b, c) memcpy(a, b, (sizeof(a)>c)?c:sizeof(a))
#define TERMSTR(a, b) a[(((sizeof(a)-1)<b)?(sizeof(a)-1):b)] = '\0'

#ifndef U64
#define U64
typedef unsigned long long u64;
#endif


/*
 * structs
 */

struct ifStruct {
    int     ignore;
    int     admin_down;
    int     index;
    int     status;
    int     type;
    char    descr[MAX_DESCR_LEN];
    char    alias[MAX_DESCR_LEN];
    char    name[MAX_DESCR_LEN];
    u64     inOctets;
    u64     inUcastPkts;
    u64     inMulticastPkts;
    u64     inBroadcastPkts;
    u64     outOctets;
    u64     outUcastPkts;
    u64     outMulticastPkts;
    u64     outBroadcastPkts;
    u64     speed;
    u64     inBitps;
    u64     outBitps;
    unsigned long   inDiscards;
    unsigned long   outDiscards;
    unsigned long   inErrors;
    unsigned long   outErrors;
    unsigned long   inCRC;
    long double     checktime;
};

struct OIDStruct {
    oid             name[MAX_OID_LEN];
    size_t          name_len;
};



/*
 * OIDs, hardcoded to remove the dependency on MIBs
 */
#define NON_REPEATERS 2
#define OID_REPEATERS 4
static char    *oid_if[] = {".1.3.6.1.2.1.1.3", ".1.3.6.1.2.1.2.1", ".1.3.6.1.2.1.2.2.1.2", ".1.3.6.1.2.1.31.1.1.1.1", ".1.3.6.1.2.1.31.1.1.1.18", ".1.3.6.1.2.1.2.2.1.3", 0}; /* "uptime", "ifNumber", "ifDescr", "ifName", "ifAlias", "ifType"  */



static char    *oid_vals[] = {
    ".1.3.6.1.2.1.2.2.1.7",     /* ifAdminStatus */
    ".1.3.6.1.2.1.2.2.1.8",     /* ifOperStatus */
    ".1.3.6.1.2.1.31.1.1.1.6",  /* ifHCInOctets */
    ".1.3.6.1.2.1.31.1.1.1.7",  /* ifHCInUcastPkts */
    ".1.3.6.1.2.1.31.1.1.1.8",  /* ifHCInMulticastPkts */
    ".1.3.6.1.2.1.31.1.1.1.9",  /* ifHCInBroadcastPkts */
    ".1.3.6.1.2.1.2.2.1.13",    /* ifInDiscards */
    ".1.3.6.1.2.1.2.2.1.14",    /* ifInErrors */
    ".1.3.6.1.4.1.9.2.2.1.1.12",/* locIfInCRC */
    ".1.3.6.1.2.1.31.1.1.1.10", /* ifHCOutOctets */
    ".1.3.6.1.2.1.31.1.1.1.11", /* ifHCOutUcastPkts */
    ".1.3.6.1.2.1.31.1.1.1.12", /* ifHCOutMulticastPkts */
    ".1.3.6.1.2.1.31.1.1.1.13", /* ifHCOutBroadcastPkts */
    ".1.3.6.1.2.1.2.2.1.19",    /* ifOutDiscards */
    ".1.3.6.1.2.1.2.2.1.20",    /* ifOutErrors */
    ".1.3.6.1.2.1.2.2.1.5",     /* ifSpeed */
    ".1.3.6.1.2.1.31.1.1.1.15", /* ifHighSpeed */
    0
    };



/*
 * prototypes
 */

void print64(struct counter64*, unsigned long*);
u64 convertto64(struct counter64 *, unsigned long *);
u64 subtract64(u64, u64);
netsnmp_session *start_session(netsnmp_session *, char *, char *);
netsnmp_session *start_session_v3(netsnmp_session *, char *, char *, char *, char *, char *, char *);
int usage(char *);
int parse_perfdata(char *, struct ifStruct *, int ifNumber);
void set_value(struct ifStruct *, char *, char *, u64, char *);
int parseoids(int, char *, struct OIDStruct *);
int create_request(netsnmp_session *, struct OIDStruct **, char **, int, netsnmp_pdu **);
void create_pdu(int, char **, netsnmp_pdu **, struct OIDStruct **, int, int);
int match_regexs(const regex_t *re, const regex_t *exre, const char *to_match);
