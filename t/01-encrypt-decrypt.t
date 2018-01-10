#!perl
use strict;
use warnings;

use NaK;

use Test::More;

sub main {
    ok(NaK::MACBYTES, "MACBYTES works");
    my @nacbytes;
    $nacbytes[0] = NaK::MACBYTES();
    $nacbytes[1] = NaK::MACBYTES;
    $nacbytes[2] = &NaK::MACBYTES;
    $nacbytes[3] = (\&NaK::MACBYTES)->();

    is_deeply(
        \@nacbytes,
        [ (NaK::MACBYTES) x 4 ],
        "Various ways of accessing the constants work"
    );

    my $keylen   = NaK::KEYBYTES();
    my $noncelen = NaK::NONCEBYTES();

    my $key   = "X" x $keylen;
    my $nonce = "N" x $noncelen;

    my $encrypt = NaK::encrypt(
        "plaintext",
        $nonce,
        $key
    );

    ok($encrypt, "Can encrypt");

    my $encrypt_again = NaK::encrypt(
        "plaintext",
        $nonce,
        $key,
    );

    is($encrypt, $encrypt_again, "re-encrypting using the same nonce gives the same cipher text");

    my $decrypted = NaK::decrypt(
        $encrypt,
        $nonce,
        $key
    );

    is($decrypted, "plaintext", "can decrypt what we previously encrypted");
}

main();

done_testing;

