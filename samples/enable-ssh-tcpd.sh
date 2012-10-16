#!/bin/sh

# Set up the hosts.allow file to permit ssh access for the IP
# that invoked this command. I assume you have something like
# "ALL: ALL" in /etc/hosts.deny, or at least "sshd: ALL"

# This is pretty simplistic, and assumes that the IP address
# we're adding isn't already present anywhere in the file...

# NOTE: this is vulnerable to a "man in the middle" attack;
# see the Ostiary FAQS at the website for details!

# Paranoia. Make sure we actually got an argument.
if [ -z $1 ]; then
  # Enable ssh for ""? I don't think so.
  exit -1;
fi

# Append the new line to the tcpd control file.
echo "#added by ostiaryd for" $1 >> /etc/hosts.allow
echo "sshd: " $1 >> /etc/hosts.allow

#Don't bother sleeping if we couldn't modify /etc/hosts.allow
if [ "$?" != 0 ]; then
  exit -1;
fi

# Sleep for five minutes.
sleep 300

# Removing the line from /etc/hosts.allow won't interrupt an
# open ssh session, but it will prevent any new ones from being
# opened. They should have logged in by now.
cat /etc/hosts.allow | grep -v $1 > /etc/hosts.allow.$$
mv /etc/hosts.allow.$$ /etc/hosts.allow
