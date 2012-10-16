#!/bin/sh

# Kill all ssh sessions, and disable remote ssh in /etc/hosts.allow

# Note: you'll need to create a 'hosts.allow.def' file with the
# default access rules (e.g. no remote access, etc.) you want.
#
# Restore a default hosts.allow with no remote entries.
if [ -r /etc/hosts.allow.def ]; then
  # Okay, the .def file exists.
  mv /etc/hosts.allow.def /etc/hosts.allow
fi

# Assumes that PIDs are no more than five digits. May not work if
# only three-digit PIDS are on system.

# If there are any ssh sessions still running, kill 'em (except
# the main ssh process).
# Get the main sshd process.
MAIN_SSH_PID=`cat /var/run/sshd.pid`
# Get all the other sshd processes.
SSHDS=`ps ax | grep sshd | grep -v grep | grep -v $MAIN_SSH_PID | cut -c 1-6`
# Tell 'em to go away.
if [ -n $SSHDS]; then
  kill $SSHDS
fi

# Give 'em a chance to die peacefully.
sleep 30

# Get any remaining sshd processes.
SSHDS=`ps ax | grep sshd | grep -v grep | grep -v $MAIN_SSH_PID | cut -c 1-6`
# I played nice. Now it's too late.
if [ -n $SSHDS]; then
  kill -KILL $SSHDS
fi
