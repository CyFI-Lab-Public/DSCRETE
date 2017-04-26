#!/bin/bash
pid=$1

offset=0

# delete old output files
rm temp.dump $pid.dump $pid.info;

kill -STOP $pid
##
# Step 1: parse proc/$pid/maps
# Step 2: for each segment, use gdb to dump memory
# Step 3: write memory to dump file
# Step 4: write mappings to .info file
##
cat /proc/$pid/maps|grep -v "\---p"|sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\)/\1 \2/p'|awk '{ print $1,'\n',$2,'\n',$7}'|while read line;do set -- $line; gdb --batch --pid $pid -ex "dump memory temp.dump 0x$1 0x$2"; cat temp.dump >> $pid.dump; size=$((0x$2-0x$1));hexoffset=`echo "obase=16;ibase=10; $offset" | bc`; 
echo $3;
if [ -z "$3" ] 
then echo "[?] $1->$size->$hexoffset" >> $pid.info 
else echo "$3 $1->$size->$hexoffset" >> $pid.info 
fi;
offset=$(($offset+$size));done;
rm temp.dump;
kill -CONT $pid
