#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* libsodium */
#include "sodium.h"

MODULE = NaK        PACKAGE = NaK

PROTOTYPES: DISABLE

BOOT:
{
    /* let's create a couple of constants for perl to use */
    HV *stash = gv_stashpvs("NaK", GV_ADD);

    newCONSTSUB(stash, "NONCEBYTES", newSViv(crypto_secretbox_NONCEBYTES));
    newCONSTSUB(stash, "KEYBYTES",   newSViv(crypto_secretbox_KEYBYTES));
    newCONSTSUB(stash, "MACBYTES",   newSViv(crypto_secretbox_MACBYTES));
}

void
encrypt(msg, nonce, key)
SV * msg
SV * nonce
SV * key
INIT:
    SV* encrypted_sv;
    STRLEN msg_len;
    STRLEN nonce_len;
    STRLEN key_len;
    STRLEN enc_len;
    unsigned char * msg_buf;
    unsigned char * nonce_buf;
    unsigned char * key_buf;
PPCODE:
{
    if ( GIMME_V == G_VOID ) {
        XSRETURN_EMPTY;
    }

    nonce_buf = (unsigned char *)SvPV(nonce, nonce_len);
    if ( nonce_len != crypto_secretbox_NONCEBYTES ) {
        croak("Invalid nonce");
    }

    key_buf = (unsigned char *)SvPV(key, key_len);
    if ( key_len != crypto_secretbox_KEYBYTES ) {
        croak("Invalid key");
    }

    msg_buf = (unsigned char *)SvPV(msg, msg_len);

    enc_len = crypto_secretbox_MACBYTES + msg_len;

    encrypted_sv = newSV(enc_len);
    SvUPGRADE(encrypted_sv, SVt_PV);
    SvPOK_on(encrypted_sv);
    SvCUR_set(encrypted_sv, enc_len);

    crypto_secretbox_easy(
        SvPVX(encrypted_sv),
        msg_buf,
        msg_len,
        nonce_buf,
        key_buf
    );

    mXPUSHs( encrypted_sv );
    XSRETURN(1);
}

void
decrypt(ciphertext, nonce, key)
SV * ciphertext
SV * nonce
SV * key
INIT:
    SV* decrypted_sv;
    STRLEN msg_len;
    STRLEN nonce_len;
    STRLEN key_len;
    STRLEN dec_len;
    unsigned char * msg_buf;
    unsigned char * nonce_buf;
    unsigned char * key_buf;
PPCODE:
{
    if ( GIMME_V == G_VOID ) {
        XSRETURN_EMPTY;
    }

    nonce_buf = (unsigned char *)SvPV(nonce, nonce_len);
    if ( nonce_len != crypto_secretbox_NONCEBYTES ) {
        croak("Invalid nonce");
    }

    key_buf = (unsigned char *)SvPV(key, key_len);
    if ( key_len != crypto_secretbox_KEYBYTES ) {
        croak("Invalid key");
    }

    msg_buf = (unsigned char *)SvPV(ciphertext, msg_len);
    if ( msg_len < crypto_secretbox_MACBYTES ) {
        croak("Invalid ciphertext");
    }
    dec_len = msg_len - crypto_secretbox_MACBYTES;

    decrypted_sv = newSV(dec_len);
    SvUPGRADE(decrypted_sv, SVt_PV);
    SvPOK_on(decrypted_sv);

    if ( crypto_secretbox_open_easy( SvPVX(decrypted_sv), msg_buf, msg_len, nonce_buf, key_buf) == 0 ) {
        SvCUR_set(decrypted_sv, dec_len);
        mXPUSHs( decrypted_sv );
        XSRETURN(1);
    }
    else {
        sv_free(decrypted_sv);
        croak("Message forged");
    }
}



