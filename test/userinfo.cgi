#!/usr/bin/perl
use strict;
use warnings;
use FindBin qw($Bin $Script);

my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
    $atime, $mtime, $ctime, $blksize, $blocks) = stat "$Bin/$Script";

print "Content-type: text/html; charset=utf-8\r\n\r\n";
print "$<:$(:$uid:$gid";

