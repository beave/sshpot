#ifndef CONFIG_H
#define CONFIG_H

#include <syslog.h>

#define LISTENADDRESS   "0.0.0.0"
#define DEFAULTPORT     22
#define RSA_KEYFILE     "./sshpot.rsa.key"
#define LOGFILE         "sshpot_auth.log"
#define DEBUG		0

#define	USER		"nobody"
#define GROUP		"nogroup"

/* the "SSH-2.0-" is automatically added by libssh! */

#define BANNER		"OpenSSH_6.7p1 Debian-5+deb8u3"

#define DELAY		2

#define SYSLOG_FACILITY	LOG_AUTH
#define SYSLOG_PRIORITY LOG_ALERT

#endif
