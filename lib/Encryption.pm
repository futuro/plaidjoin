package Encryption;

require "Files.pm";

use subs qw(
    deduce_linux_enc_info deduce_solaris_enc_info deduce_and_set_enc_types );

# Find out what encryption formats are supported in linux
# TODO: I can't decide if I would prefer to have an 'if' block to deal with the case
#       where $^O ne "linux", thus reducing the nest level of the routine. The downside
#       is that then I have two exit points from the routine, which can increase work if
#       I every decide that the exit value should change. Maybe the readability tradeoff is
#       worth it though...
# NOTE: This will look for aes, des and arcfour support, though it will only report
#       the min and max key size for aes.
# Input:
#   N/A
# Output:
#   Hash: The supported encryption types
sub deduce_linux_enc_info {
    my %enc_info;

    if ($^O eq "linux") {
        my @modules = qx(lsmod);
        MODULE:
        foreach (@modules) {
            next unless /^(?:aes|des|arc4)/;

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

            (${enc_info}{des} = 1)  if (/^des/);
            (${enc_info}{arc4} = 1) if (/^arc4/);
        }
    }
    else {
        print qq(This function should only be called from a linux system, but \$^O says $^O\n);
        print qq(No encryption types found\n);
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

    if ($^O eq "solaris") {
        my @crypto = qx(encrypt -l);
        foreach (@crypto) {
            if (/^aes\s+(\d+)\s+(\d+)/) {
                ${enc_info}{aes} = 1;
                ${enc_info}{minkeysize} = $1;
                ${enc_info}{maxkeysize} = $2;
            }
            (${enc_info}{des} = 1)  if (/^des/);
            (${enc_info}{arc4} = 1) if (/^arcfour/);
        }
    }
    else {
        print qq(This function should only be called from a solaris system, but \$^O says $^O\n);
        print qq(No encryption types found\n);
    }

    return %enc_info;
}

# Sets the encryption type in the ldap object
# TODO: Write this comment header
sub deduce_and_set_enc_types {
    my $upcase_nodename    = (shift or '');
    my $baseDN             = (shift or '');
    my $krb5ccname         = (shift or '');
    my $domain_controller  = (shift or '');
    my $object_file        = (shift or generate_tmpfile("enc_obj.XXXXXX"));
    my $dryrun             = (shift or 0);

    my $aes128_supported;
    my $aes256_supported;
    my $object;
    my $val;

    my %enc_info;
    my @enc_types;

    my $ldap_options = qq(-Q -Y gssapi);
    $krb5ccname = "KRB5CCNAME=$krb5ccname" unless !$krb5ccname;

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
        die   "Maybe add support for $^O in subroutine 'set_enc_type'.\n";
    }

    if (${enc_info}{minkeysize} == 128 and ${enc_info}{maxkeysize} == 256) {
        $val              = "00000018";
        $aes128_supported = 1;
        $aes256_supported = 1;
    }
    elsif (${enc_info}{minkeysize} == 128) {
        $val              = "00000008";
        $aes128_supported = 1;
        $aes256_supported = 0;
    }
    elsif (${enc_info}{maxkeysize} == 256) {
        $val              = "00000010";
        $aes128_supported = 0;
        $aes256_supported = 1;
    }
    else {
        $aes128_supported = 0;
        $aes256_supported = 0;
    }

    $object = <<ENDOBJECT;
dn: CN=$upcase_nodename,$baseDN
changetype: modify
add: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: $val
ENDOBJECT

    open FH, ">$object_file" or die "Couldn't open $object_file: $!";
    print FH $object;
    close FH;

    if (!$dryrun) {
        system(qq($krb5ccname ldapmodify -h "$domain_controller" $ldap_options -f "$object_file"));
        if ($? != 0) {
            $aes128_supported = 0;
            $aes256_supported = 0;
            print "AES doesn't seem to be supported by the domain controller.\n";
            print "Assuming 1DES and Arcfour encryption types.\n";
        }
    }

    # Add the strongest encryption types first
    $aes256_supported and push(@enc_types, "aes256-cts-hmac-sha1-96");
    $aes128_supported and push(@enc_types, "aes128-cts-hmac-sha1-96");

    $aes256_supported and print "AES-256 is supported.\n";

    # Apparently AD prefers Arcfour, so that comes next
    if (${enc_info}{arc4}) {
        push @enc_types, "arcfour-hmac-md5";
        print "Arcfour is supported.\n";
    }
    else {
        print "Arcfour is not supported.\n";
    }

    if (${enc_info}{des}) {
        push @enc_types, "des-cbc-crc";
        push @enc_types, "des-cbc-md5";
    }

    if (!@enc_types) {
        warn "No encryption types supported.\n";
        die  "Please enable AES-128, AES-256, Arcfour, or DES support, then re-join.\n";
    }

    return @enc_types;
}

1;
# vim: ts=4 sw=4 et fdm=syntax
