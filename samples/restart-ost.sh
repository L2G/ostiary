#!/bin/sh

# This script determines the PID of the currently-running ostiaryd
# process and sends it the HUP signal, upon which it should reinitialize
# itself.
#
# You may need to update the location of the PIDfile if you have
# changed it from the default.
#
OST_PID=`cat /var/run/ostiaryd.pid`
if [ $OST_PID ]; then
  echo Sending HUP signal to process ${OST_PID}.
  kill -HUP $OST_PID
else
  echo No ostiaryd process running.
fi
