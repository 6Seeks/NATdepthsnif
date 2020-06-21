#!/bin/bash
# chkconfig: 2345 66 77 
# processname:sniff       
# Description:  This shell script takes care of starting and stopping sniff 
# yangtap created on 5/6/2020
#




do_start()
{
  echo "start"
  ./script.sh
}
 
do_stop()
{
 
	echo "stop ????"
 
}
 
 
#
# Function that sends a SIGHUP to the daemon/service
#
do_restart() {
	do_stop
	sleep 1
	do_start
}
 
case "$1" in
  start)
	do_start
	;;
  stop)
	do_stop
	;;
  status)
	exit $?
	;;
  reload)
	echo "reload"
    do_restart
	;;
  restart)
    echo "restart"
	do_restart
	;;
  *)
	echo "Usage: {start|stop|restart|reload}" >&2
	exit 3
	;;
esac
 
exit 0
