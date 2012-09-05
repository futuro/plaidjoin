package Encryption;

use strict;
use warnings;

use FindBin qw($Bin);
FindBin::again();
use lib "$Bin";

use Files;
use LDAP;

use subs qw(
    deduce_linux_enc_info deduce_solaris_enc_info deduce_and_set_enc_types );

BEGIN {
    require Exporter;

    # Inherit from Exporter to export functions and variables
    our @ISA = qw(Exporter);

    # Functions and variables which are exported by default
    our @EXPORT = qw( deduce_linux_enc_info deduce_solaris_enc_info deduce_and_set_enc_types );
}

# Find out what encryption formats are supported in linux
# TODO: I can't decide if I would prefer to have an 'if' block to deal with the case
#       where $^O ne "linux", thus reducing the nest level of the routine. The downside
#       is that then I have two exit points from the routine, which can increase work if
#       I every decide that the exit value should change. Maybe the readability tradeoff is
#       worth it though...
# Input:
#   N/A
# Output:
#   Hash: The supported encryption types
sub deduce_linux_enc_info {
    my %enc_info;

    if ($^O ne "linux") {
        print qq(This function should only be called from a linux system, but \$^O says $^O\n);
        print qq(No encryption types found\n);
        return %enc_info;
    }

    my @modules = qx(lsmod);
    MODULE:
    foreach (@modules) {
        # Check if we have aes support, and if so, find out our min and max
        # key size, converting from bytesize to bitsize.
        if (/^aes/) {
            ${enc_info}{aes} = 1;

            # It's possible that 'aes' will show up more than once, such as 'aes_x86_64'
            # and 'aes_generic'. If we've already found the necessary info, we don't need
            # to look for it again.
            next if (${enc_info}{minkeysize} and ${enc_info}{maxkeysize});

            my $in_aes;

            my @crypto = qx'cat /proc/crypto|grep "name\|keysize"';
            foreach (@crypto) {
                next unless (/^name\s+:\s+aes/ or $in_aes);

                # If we hit a new name section, we're no longer 'in_aes', and should skip until
                # we hit a new aes section (if any)
                if (/^name\s+:\s+(?!aes)/) {
                    $in_aes = 0;
                    next;
                }

                $in_aes = 1;

                /^min keysize\s+:\s+(\d+)/ and ${enc_info}{minkeysize} = ($1 * 8);
                /^max keysize\s+:\s+(\d+)/ and ${enc_info}{maxkeysize} = ($1 * 8);

                # If we've found the key sizes, don't hang about.
                    last if (${enc_info}{minkeysize} and ${enc_info}{maxkeysize});
            }
        }
    }

    return %enc_info;
}

# Find out what encryption formats are supported in solaris
# NOTE: This will look for aes, des and arcfour support, though it will only report
#       the min and max key size for aes.
# Input:
#   N/A
# Output:
#   Hash: The supported encryption types
sub deduce_solaris_enc_info {
    my %enc_info = {};

    if ($^O ne "solaris") {
        print qq(This function should only be called from a solaris system, but \$^O says $^O\n);
        print qq(No encryption types found\n);
        return %enc_info;
    }

    my @crypto = qx(encrypt -l);
    foreach (@crypto) {
        if (/^aes\s+(\d+)\s+(\d+)/) {
            ${enc_info}{aes} = 1;
            ${enc_info}{minkeysize} = $1;
            ${enc_info}{maxkeysize} = $2;
        }
    }

    return %enc_info;
}

# Sets the encryption type in the ldap object
# TODO: Write this comment header
sub deduce_and_set_enc_types {
    my $ldap              = (shift or '');
    my $upcase_nodename   = (shift or '');
    my $baseDN            = (shift or '');
    my $dryrun            = (shift or 0);

    my $aes128_supported;
    my $aes256_supported;
    my $val;

    my %enc_info;
    my @enc_types;

    my $distinct_name = "CN=$upcase_nodename,$baseDN";
    my $result;

    if ($^O eq "linux") {
        %enc_info = deduce_linux_enc_info();
    }
    elsif ($^O eq "solaris") {
        %enc_info = deduce_solaris_enc_info();
    }
    else {
        print "This function currently only supports linux and solaris OSs.\n";
        print "However, you're running $^O, according to perl.\n";
        print "I haven't really decided what to do in this case, so let's just die.\n";
        die   "Maybe add support for $^O in subroutine 'deduce_and_set_enc_type'.\n";
    }

    if (!%enc_info){
        die "No supported encryption types found; quitting";
    }

    if (${enc_info}{minkeysize} == 128 and ${enc_info}{maxkeysize} == 256) {
        $val              = 0x18;
        $aes128_supported = 1;
        $aes256_supported = 1;
    }
    elsif (${enc_info}{minkeysize} == 128) {
        $val              = 0x8;
        $aes128_supported = 1;
        $aes256_supported = 0;
    }
    elsif (${enc_info}{maxkeysize} == 256) {
        $val              = 0x10;
        $aes128_supported = 0;
        $aes256_supported = 1;
    }
    else {
        $aes128_supported = 0;
        $aes256_supported = 0;
    }

    if (!$dryrun) {
        $result = ldapreplace( $ldap, $distinct_name, { 'msDS-SupportedEncryptionTypes' => $val } );
        if ($result->code){
            warn "Failed to replace entry msDS-SupportedEncryptionTypes: ", $result->error;
            warn "LDAP error code: ".$result->code."\n";
            warn "LDAP error text: ".$result->error_text."\n\n";
            warn "AES doesn't seem to be supported by the domain controller.\n";
            die  "No other encryption types are currently supported; dying.\n";
        }
    }

    # Add the strongest encryption types first
    $aes256_supported and push(@enc_types, "aes256-cts-hmac-sha1-96");
    $aes128_supported and push(@enc_types, "aes128-cts-hmac-sha1-96");

    $aes256_supported and print "AES-256 is supported.\n";

    if (!@enc_types) {
        warn "No encryption types supported on the client.\n";
        die  "Please enable AES-256/AES-128 then re-join.\n";
    }

    return @enc_types;
}

1;
# vim: ts=4 sw=4 et fdm=syntax
