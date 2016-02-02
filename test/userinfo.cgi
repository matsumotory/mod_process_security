#!/usr/bin/perl
use strict;
use warnings;

my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
    $atime, $mtime, $ctime, $blksize, $blocks) = stat $fname;

print "Content-type: text/html; charset=utf-8\r\n\r\n";
print "$<:$(:$uid:$gid";

