#!perl
use strict;
use warnings;

use Test::More;
use Test::Exception;

use NaK;

my $k = "K" x NaK::KEYBYTES();
my $n = "N" x NaK::NONCEBYTES();

my $bad_arity = qr/\Qencrypt() must be passed a message, a nonce, and a key\E/;

throws_ok { NaK::encrypt() } $bad_arity, "no args";
throws_ok { NaK::encrypt("") } $bad_arity, "1 arg";
throws_ok { NaK::encrypt("", "") } $bad_arity, "2 args";

TODO: {
    local $TODO = "Arity checks are broken for > 3 args";
    throws_ok { NaK::encrypt("", "", "", "") } $bad_arity, "4 args";
    my @args = ("" x 66);
    throws_ok { NaK::encrypt(@args) } $bad_arity, "array of args";
}

throws_ok { NaK::encrypt("", "bad noncexxx", $k) } qr/Invalid nonce/;
throws_ok { NaK::encrypt("", $n, "bad key") } qr/Invalid key/;

throws_ok { NaK::decrypt("", $n, $k) } qr/Invalid ciphertext/;

done_testing;
