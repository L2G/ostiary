#!/bin/sh

# This script determines the PID of the currently-running ostiaryd
# process and sends it the HUP signal, upon which it should reinitialize
# itself.
#
# This version does not use the pidfile that ostiaryd creates, and instead
# tries to grep the output of ps to find it. It won't work correctly if
# there is more than one 'ostiaryd' process running.
#
OST_PID=`ps -ef | grep ostiaryd | grep -v grep | awk '{print $2}'`
if [ $OST_PID ]; then
  echo Sending HUP signal to process ${OST_PID}.
  kill -HUP $OST_PID
else
  echo No ostiaryd process running.
fi
