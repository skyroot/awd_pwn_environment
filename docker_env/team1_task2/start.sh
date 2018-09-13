#!/bin/sh
# Add your startup script

# DO NOT DELETE
service ssh restart;
/etc/init.d/xinetd start;
sleep infinity;
