#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>
#include <libssh/libssh.h>

#define MAXBUF 100

struct connection {
    ssh_session session;
    ssh_message message;
    char client_ip[MAXBUF];
    char con_time[MAXBUF];
    char *user;
    char *pass;
};

int handle_auth(ssh_session session, char *logfile, bool syslog, int delay);
void drop_priv(char *user, char *group); 
void sshpot_chroot (const char *chrootdir);

#endif
