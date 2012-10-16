#
# Regular cron jobs for the ostiary package
#
0 4	* * *	root	[ -x /usr/bin/ostiary_maintenance ] && /usr/bin/ostiary_maintenance
