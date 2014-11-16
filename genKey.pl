#!/usr/bin/perl

use strict;
use warnings;

use Crypt::CBC;

my $key = Crypt::CBC->random_bytes(56);
my $iv = Crypt::CBC->random_bytes(8);

my $unpackedKey = unpack("H*", $key);
my $unpackedIv = unpack("H*", $iv);

open(OUT, ">key");

print(OUT "key: $unpackedKey\n");
print(OUT "iv: $unpackedIv\n");
