/*
 * Created by yeholmes@outlook.com
 *
 * Simple deamon replacer
 */

#ifndef REPLACER_DAEMON_H
#define REPLACER_DAEMON_H

#ifndef REPLACER_PIDFILE
#define REPLACER_PIDFILE     "/var/lock/replacer.lock"
#endif

#ifndef REPLACER_APP
#define REPLACER_APP         "/bin/ls"
#endif

#define REPLACER_LOCKFD      "FT_LOCKFD"

int should_fork_daemon(void);

void fork_master(int fd);

void setup_replacer(void);

#endif
