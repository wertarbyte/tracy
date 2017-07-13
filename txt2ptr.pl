#!/usr/bin/perl
# txt2ptr.pl
#
# generate reverse DNS zone for use with tracy
#
# Stefan Tomanek <stefan.tomanek@wertarbyte.de>

use strict;

while (my $line = <>) {
	chomp($line);
	if ($. > 256) {
		die "tracy won't be able to handle more than 256 hops\n";
	}
	my $ptr = join('.', reverse split(//, sprintf "%02x", ($.-1)));
	print "$ptr\tIN\tPTR\t$line.\n";
}
