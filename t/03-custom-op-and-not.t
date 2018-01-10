#!perl
use strict;
use warnings;

use Test::More;
use Data::Dumper;

use NaK;

sub lived_ok ($) { pass($_[0]) }

sub main {
    my $k = "K" x NaK::KEYBYTES();
    my $n = "N" x NaK::NONCEBYTES();
    my $v = "original value do not steal $$";
    my @args = ($v, $n, $k);

    subtest "encrypt" => sub {
        my $e = \&NaK::encrypt;
        my @encrypt;
        $encrypt[0] = NaK::encrypt($v, $n, $k);
        lived_ok("custom op");

        $encrypt[1] = &NaK::encrypt($v, $n, $k);
        lived_ok("xs func");

        $encrypt[2] = $e->($v, $n, $k);
        lived_ok("xs func via ref");

        $encrypt[3] = NaK::encrypt(@args);
        lived_ok("custom op with list args");

        $encrypt[4] = &NaK::encrypt(@args);
        lived_ok("xs func with list args");

        $encrypt[5] = $e->(@args);
        lived_ok("xs func via ref with list args");

        push @encrypt, NaK::encrypt($v, $n, $k);
        lived_ok("custom op list context");

        push @encrypt, &NaK::encrypt($v, $n, $k);
        lived_ok("xs func list context");

        push @encrypt, $e->($v, $n, $k);
        lived_ok("xs func via ref list context");

        push @encrypt, NaK::encrypt(@args);
        lived_ok("custom op list context list args");

        push @encrypt, &NaK::encrypt(@args);
        lived_ok("xs func list context list args");

        push @encrypt, $e->(@args);
        lived_ok("xs func via ref list context list args");

        my %seen; $seen{$_}++ for @encrypt;
        is(keys(%seen), 1, "all variations of encrypt give the same result")
            or diag(Dumper(\@encrypt));
    };

    $v = $args[0] = NaK::encrypt($v, $n, $k);
    subtest "decrypt" => sub {
        my $e = \&NaK::decrypt;
        my @decrypt;
        $decrypt[0] = NaK::decrypt($v, $n, $k);
        lived_ok("custom op");

        $decrypt[1] = &NaK::decrypt($v, $n, $k);
        lived_ok("xs func");

        $decrypt[2] = $e->($v, $n, $k);
        lived_ok("xs func via ref");

        $decrypt[3] = NaK::decrypt(@args);
        lived_ok("custom op with list args");

        $decrypt[4] = &NaK::decrypt(@args);
        lived_ok("xs func with list args");

        $decrypt[5] = $e->(@args);
        lived_ok("xs func via ref with list args");

        push @decrypt, NaK::decrypt($v, $n, $k);
        lived_ok("custom op list context");

        push @decrypt, &NaK::decrypt($v, $n, $k);
        lived_ok("xs func list context");

        push @decrypt, $e->($v, $n, $k);
        lived_ok("xs func via ref list context");

        push @decrypt, NaK::decrypt(@args);
        lived_ok("custom op list context list args");

        push @decrypt, &NaK::decrypt(@args);
        lived_ok("xs func list context list args");

        push @decrypt, $e->(@args);
        lived_ok("xs func via ref list context list args");

        my %seen; $seen{$_}++ for @decrypt;
        is(keys(%seen), 1, "all variations of decrypt give the same result")
            or diag(Dumper(\@decrypt));
    };
}

main();

done_testing;

