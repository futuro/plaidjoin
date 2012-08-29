package Kerberos;

use strict;
use warnings;

use Authen::Krb5;

use Term::ReadLine;
use Term::ReadKey;

use Net::Domain      qw(hostfqdn);
use String::MkPasswd qw(mkpasswd);
use File::Copy       qw(cp);
use File::Temp       qw(tempfile);

use subs qw(
    setup_krb_files kinit kt_write generate_and_set_passwd construct_krb5_conf
    get_creds_with_passwd );

BEGIN {
    require Exporter;

    # Inherit from Exporter to export functions and variables
    our @ISA = qw(Exporter);

    # Functions and variables which are exported by default
    our @EXPORT = qw(
        setup_krb_files kinit kt_write generate_and_set_passwd construct_krb5_conf
        get_creds_with_passwd );
}

my $def_ktab = '/tmp/plaidjoin.keytab';

# Construct the contents of the new krb5.conf file, write them into a temp file,
# then return that file name.
# Input:
#   Array[Hash] : The list of KDCs
#   Str         : The kpasswd server string
#   Str         : The realm we're connecting to
#   Str         : The template to use when constructing the temp file (Optional)
# Output:
#   Str         : The name of the temporary file
#   OR
#   ''          : Nothing was passed to the function, so nothing was constructed
sub construct_krb5_conf {
    my @KDClist  = @{(shift || [])};
    my $kpasswd  = (shift || '');
    my $domain   = (shift || '');
    my $realm    = (shift || '');
    my $template = (shift || 'plaidjoin-krb5.conf.XXXXXX');

    my $fh;
    my $filename;

    my $krb5conf   = '';
    my $kdcstrings = "";

    if (!@KDClist || !$kpasswd || !$realm) {
        warn "Missing KDClist, kpasswd, and realm entries in construct_krb5_conf.\n";
        warn "Returning the empty list.\n";
        return '';
    }

    for my $pair (@KDClist) {
        $kdcstrings .= "kdc = ${$pair}{name}\n\t";
    }
    # TODO: Is there a better way to do this?
    $kdcstrings =~ s/\n\t$//;

    $krb5conf = <<ENDCONF;
[libdefaults]
    default_realm = $realm

[realms]
    $realm = {
        $kdcstrings
        admin_server = $kpasswd
        kpasswd_server = $kpasswd
        kpasswd_protocol = SET_CHANGE
    }

[domain_realm]
    .$domain = $realm
    $domain = $realm
ENDCONF

    ($fh, $filename) = tempfile( $template, DIR => '/tmp' );
    print $fh $krb5conf;
    close $fh;

    return $filename;
}

# Creates and sets the ldap machine password
# NOTE: If all of the minimum options ($minnum et.al.) add up to more than
#       $passlen, $passlen will be divided by the number of options, converted to
#       an int, and then the minimums will be set to that number.
# Input:
#   Str : The file name for the kerberos ticket cache
#   Str : The realm we're associating with
#   Bool: Whether this is a dryrun or not
#   Num : The length of the password to use
#   Num : The minimum number of number characters to use
#   Num : The minimum number of lower case characters to use
#   Num : The minimum number of upper case characters to use
#   Num : The minimum number of special characters to use
# Output:
#   Str : The new machine password
sub generate_and_set_passwd {
    my $realm      = (shift or '');
    my $dryrun     = (shift or '');
    my $passlen    = (shift or 80);
    my $minnum     = (shift or 15);
    my $minlower   = (shift or 15);
    my $minupper   = (shift or 15);
    my $minspecial = (shift or 15);

    my $fqdn = hostfqdn();

    my $userPrincipalName = $fqdn."@".$realm;

    my $escaped_machine_passwd;
    my $machine_passwd;

    # If the specified minimums are greater than the password length, divide the password
    # length by four (the number of options), make it an int (which truncates the number),
    # and set all of the minimums to that.
    if (($minlower + $minnum + $minupper + $minspecial) > $passlen) {
        my $diff = int($passlen/4);
        $minlower   = $diff;
        $minnum     = $diff;
        $minupper   = $diff;
        $minspecial = $diff;
    }

    # Generate a random password with a length of 80 and at least 15 numbers, lower case letters,
    # upper case letters and special characters. The other 20 characters are filled randomly.
    $machine_passwd = mkpasswd(
        -length     => $passlen,
        -minnum     => $minnum,
        -minlower   => $minlower,
        -minupper   => $minupper,
        -minspecial => $minspecial );
    # XXX: The potential issue with this method is that the machine password will
    #      show up in the ps list, atleast for as long as it takes to set the password.
    #      A possible alternative would be to open ksetpass with a pipe, then write to the pipe.
    #      TODO: Something like what I just described, or maybe implement ksetpass in perl so
    #            everything is internal.
    if (!$dryrun) {
        ($escaped_machine_passwd = $machine_passwd) =~ s/([[:punct:]])/\\$1/g;
        system(qq(echo -n $escaped_machine_passwd |ksetpass host/$userPrincipalName)) == 0
            or die "ERROR: Could not set the machine password; dying: ";
    }

    return $machine_passwd;
}

# Move over the configuration and keytab files
# Input:
#   Str  : Location of the config files
#   Str  : Location of the keytab file
#   Bool : Whether we're doing a dryrun (default: False)
#   Bool : Whether we're being verbose (default: False)
# Output:
#   N/A
sub setup_krb_files {
    my $krb5_conf    = (shift or '');
    my $keytab       = (shift or '');
    my $dryrun       = (shift or 0);
    my $verbose      = (shift or 0);

    # If this is a dryrun, just return
    if ($dryrun) {
        return;
    }

    my $default_conf   = "/etc/krb5.conf";
    my $default_keytab = "/etc/krb5.keytab";

    my $conf_mode   = 0644;
    my $keytab_mode = 0600;

    if (-e "$default_conf") {
        cp("$default_conf", "$default_conf-pre-plaidjoin");
    }

    if (-e "$default_keytab") {
        cp("$default_keytab", "$default_keytab-pre-plaidjoin");
    }

    if ( cp($krb5_conf, $default_conf) ) {
        chmod $conf_mode, $default_conf;
    }
    else {
        warn "Unable to copy $krb5_conf to $default_conf.";
    }
    if ( cp($keytab, $default_keytab) ) {
        chmod $keytab_mode, $default_keytab;
    }
    else {
        warn "Unable to copy $keytab to $default_keytab.";
    }
}

sub get_creds_with_ktab {
    my $princname = (shift or '');
    my $ktabname  = (shift or $def_ktab);
}

# Get and return initial credentials for '$princname', using either '$passwd' or STDIN
# Input:
#   Scalar: The principal name to get the credentials for
#   Scalar: The password to use (optional)
# Output:
#   Scalar: The object representation of the credentials
sub get_creds_with_passwd {
    my $princname = (shift or '');
    my $passwd    = (shift or '');

    my $princ = Authen::Krb5::parse_name( $princname )
        or die "Couldn't generate principal object from '$princname'; dying. $!";

    if (!$passwd) {
        # Get the password from the user
        print "Getting initial TGT for '".$princ->data."@".$princ->realm."'\n";
        print "Please enter your password: ";
        ReadMode('noecho');
        $passwd = ReadLine(0);
        chomp $passwd;
        ReadMode('restore');
        print "\n";
        not defined $passwd and die "Couldn't retrieve password from user; dying. $!";
    }

    # Get the initial credentials
    my $creds = Authen::Krb5::get_init_creds_password($princ, $passwd)
        or die "Couldn't get the initial credentials for '$princname'; dying. $!";
    undef $passwd; # Clear the password so we're not storing sensitive plaintext data in memory

    return $creds;
}

# Initialize the Kerberos context and cache a TGT for the principal
# Input:
#   Scalar: The principal name to get a TGT for
#   Scalar: The location of the Credentials Cache
sub kinit {
    my $princname = (shift or '');
    my $ccname    = (shift or 'FILE:/tmp/plaidjoin.hostcc');

    Authen::Krb5::init_context()
        or die "Couldn't initialize Kerberos context; dying. $!";

    my $princ = Authen::Krb5::parse_name( $princname )
        or die "Couldn't generate principal object from '$princname'; dying. $!";

    my $creds = get_creds_with_passwd( $princname );

    # Store those creds in $ccname
    my $ccache = Authen::Krb5::cc_resolve( $ccname )
        or die "Couldn't resolve initial credential cache '$ccname'; dying. $!";
    Authen::Krb5::Ccache::initialize($ccache, $princ)
        or die "Couldn't initialialize credentials cache '$ccache' for '$princ'; dying. $!";
    $ccache->store_cred($creds)
        or die "Couldn't store initial credentials in '$ccname'; dying. $!";

    return 1;
}

# Create a keytab file for the machine account
# Input:
#   Str : The password for the machine account
#   Str : the fqdn for the machine
#   Str : the realm for the machine
#   Num : the kvno for the machine
#   Str : The keytab filename for the machine
# Output:
#   N/A
sub kt_write {
    my $password   = (shift or '');
    my $fqdn       = (shift or '');
    my $realm      = (shift or '');
    my $kvno       = (shift or 1);
    my $keytab     = (shift or $def_ktab);
    my $hostccname = (shift or 'FILE:/tmp/plaidjoin.hostcc');

    my $host_principal = "host/".$fqdn."@".$realm;

    # TODO: This seems like the wrong place to have this. I should think some more about having a
    # 'kinit' function that will handle this context initiation, along with the getting creds
    # from the user (not the host creds, mind you).
    my $cprinc = Authen::Krb5::parse_name( $host_principal );
    my $ccache = Authen::Krb5::cc_resolve( $hostccname );

    # Get the initial TGT for the host using the password
    my $creds = get_creds_with_passwd( $host_principal, $password );
    Authen::Krb5::Ccache::initialize( $ccache, $cprinc );
    $ccache->store_cred($creds);

    # Write out the keytab for the stored credentials
    my $ktab = Authen::Krb5::kt_resolve( $keytab );
    my $ktentry = Authen::Krb5::KeytableEntry->new( $cprinc, $kvno, $creds->keyblock() );
    $ktab->add_entry( $ktentry );
}

1;
# vim: ts=4 sw=4 et fdm=syntax
