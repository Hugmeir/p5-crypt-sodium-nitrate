#!perl
use strict;
use warnings;

use NaK;
use Test::More;

BEGIN {
    my $have_nacl = 0;
    eval {
        require Crypt::NaCl::Sodium;
        $have_nacl = 1;
        1;
    };
    if ( !$have_nacl ) {
        plan("skip_all" => "No NaCl");
    }
}

sub main {
    my $value = "$$ + plaintext";
    my $key   = "X" x NaK::KEYBYTES();
    my $nonce = "N" x NaK::NONCEBYTES();

    my $secretbox = Crypt::NaCl::Sodium->secretbox;

    my $nacl_encrypted = $secretbox->encrypt($value, $nonce, $key);
    my $nak_encrypted  = NaK::encrypt($value, $nonce, $key);

    is($nacl_encrypted, $nak_encrypted, "NaK & NaCl return the same cipher");

    my $nacl_decrypt_nak = $secretbox->decrypt($nak_encrypted, $nonce, $key);
    my $nak_decrypt_nacl = NaK::decrypt($nacl_encrypted, $nonce, $key);

    is($nacl_decrypt_nak, $value, "nacl can decrypt nak");
    is($nak_decrypt_nacl, $value, "nak can decrypt nacl");
}

main();

done_testing;
