#!/bin/bash

echo -ne "Content-Type: text/html; charset=UTF-8\r\n\r\n"

uid=`id -u`
gid=`id -g`
groups=`id -G`

echo -n "$uid:$gid:$groups"
