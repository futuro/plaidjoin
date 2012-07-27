#!/usr/bin/perl

use strict;
use warnings;

use Carp;
use English;

use sigtrap qw(die INT QUIT);

use Getopt::Long;
use Pod::Usage;

use Net::Domain qw(hostname hostfqdn hostdomain);
use Net::DNS;

use File::Temp qw(tempfile);

my $option_results;

# Defaults
my $cname_template="adjoin-krb5ccache.XXXXXX";
my $container="CN=Computers";
my $cprinc="Administrator";
my $fqdn=hostfqdn();
my $keytab_template="adjoin-krb5keytab.XXXXXX";
my $ldap_args="-o authzid= -o mech=gssapi"; # TODO: Verify these are actually correct
my $nodename=hostname();
my $nssfile="/etc/nsswitch.conf";
my $object_template="adjoin-computer-object.XXXXXX";
my $port=3268;
my $userAccountControlBASE=4096;
#my osvers=$(uname -r); # I don't think this will be necessary in the port

# Bools
my $help='';
my $man='';

my $debug='';
#my $debug_shell='';
my $dryrun=''; # TODO: There should be a wrapper function to enable dryrun functions
my $extra_force='';
my $force='';
my $ignore_existing='';
my $leave='';
my $modify_existing='';
my $verbose='';

my $add_account="1";
my $join="1";
# There will be a "dryrun" type function to enforce the dryrun option. As such, there will be just
# 'dryrun', and no 'notdryrun'.
#my $notdryrun="1"; # This is a bool that represents whether we are doing a dry run. See dryrun
my $do_config="1";
#my $verbose_cat="1";

# Placeholder vars
my $baseDN='';
my @DClist=();
my $dnssrv='';
my $domain='';
my $domain_controller='';
my $DomainDnsZones='';
my $forest='';
my $ForestDnsZones='';
my $global_catalog='';
my @GClist=();
my $kdc='';
my @KDClist=();
my $kpasswd='';
my @KPWlist=();
my $krb5ccname='';
my $krb5conf='';
my $netbios_nodename='';
my $new_keytab='';
my $object='';
my $realm='';
my $site=''; # This variable is never used in adjoin.sh
my $site_name='';
my $upcase_nodename='';

# Do some cleanup if we're exiting
END {
    my $exitval = $?;
    print "Cleaning up.\n";
    # Make sure we're only removing files in /tmp
    # This probably isn't 100%, super-duper-ultra-mega secure, but I hope it's secure enough that
    # to accidentally shoot yourself in the foot with a messed up '$krb5ccname' would be /almost/
    # impossible.
    if ( $krb5ccname =~ m:/tmp/\w+:) {
        # We don't care whether these succeed or not
        system("kdestroy -q -c $krb5ccname") if $krb5ccname;
        system("rm -f $krb5ccname")          if $krb5ccname;
    }
    $? = $exitval;
}

if ($PROGRAM_NAME eq "adleave"){
    $leave=1;
}

# Do some OpenSolaris configuration stuff
# XXX XXX: I don't have access to an OpenSolaris box, so I make no assurances that this
#          code works, or does anything, or doesn't do every possible bad thing.
#          Use at your own risk.
# Input:
#   N/A
# Output:
#   1: Success (always)
sub doIDMAPconfig {
    my $dryrun = (shift or 0);
    my $leave  = (shift or 0);

    system("svcs -l svc:/system/idmap >/dev/null 2>/dev/null");
    # SNV/OpenSolaris
    if ($? == 0) {
        if ($leave) {
            system("svcadm disable -s svc:/system/idmap") unless $dryrun;
        }
        else {
            system("svcadm disable -ts svc:/system/idmap") unless $dryrun;
            system("svcadm enable -t svc:/system/idmap") unless $dryrun;
        }
    }

    return 1;
}

# Deduce whether there is an existing machine account
# NOTE: I created this function to help try and control some of the wild growth in adjoin.sh.
#       This function is un good, and I'm not 100% certain how I want to ultimately deal
#       with this code. So, I did the rough equivalent of sweeping it under the rug. It's still
#       a problem, and I've named it so it should stick out.
# Input:
#   I dunno lol.
# Output
#   ????????
sub sleuth_machine_bad_times {
    my $baseDN            = (shift or '');
    my $netbios_nodename  = (shift or '');
    my $ccname            = (shift or '');
    my $domain_controller = (shift or '');
    my $ignore_existing   = (shift or 0);
    my $modify_existing   = (shift or 0);
    my $extra_force       = (shift or 0);
    my $leave             = (shift or 0);
    my $verbose           = (shift or 0);

    $ccname = "KRB5CCNAME=$ccname";

    my $distinct_name = '';

    my $ldap_options = '';
    my @results = ();

    if (!$dryrun) {
        print "Checking for an existing account.\n";
        $ldap_options = qq(-Q -Y gssapi -b "$baseDN" -s sub sAMAccountName="$netbios_nodename" dn);
        @results = qx(ldapsearch -h $domain_controller $ldap_options);

        for my $answer (@results) {
            next unless ($answer =~ s/^dn: (.+)/$1/);

            $distinct_name = $1;
            last;
        }
    }

    if (!$distinct_name) {
        $ignore_existing = 0;
        $modify_existing = 0;
    }

    # If $ignore_existing is false and $modify_existing is false and $distinct_name exists
    if ( (!$ignore_existing eq !0) and (!$modify_existing eq !0) and $distinct_name ) {
        print "Inspecting machine account for other objects.\n";

        $ldap_options = qq(-Q -Y gssapi -b "$distinct_name" -s sub "" dn);
        @results = qx($ccname ldapsearch -h $domain_controller $ldap_options);
        for my $answer (@results) {
            next unless (($answer =~ s/^dn: (.+)/$1/) and ($distinct_name ne $answer));

            $answer =~ /$distinct_name(.*)/;
            my $sub_dn = $1;

            if ($extra_force) {
                print "Deleting the following object: $sub_dn\n";
                system(qq($ccname ldapdelete -h "$domain_controller" $ldap_options "$answer"));
            }
            else {
                print "The following object must be deleted (use -f -f, -r or -i): $sub_dn\n";
            }
        }

        if ($force or $leave) {
            print "Deleting existing machine account.\n";
            system(qq($ccname ldapdelete -h "$domain_controller" $ldap_options "$distinct_name"));
        }
        elsif (!$modify_existing or !$ignore_existing) {
            warn "A machine account already exists. Try -i, -r or -f (see usage). Quitting.\n";
            exit 1;
        }
    }

    if ($leave) {
        doIDMAPconfig(); # This is specifically for SNV/OpenSolaris
        my $base = ($0 =~ m|\./(.*)+|);
        print "$base: Done\n";
        exit 0;
    }
}

# Return the length of a netmask
# Input:
#   Scalar: The netmask to measure
# Output:
#   Scalar: The length of the netmask
#   OR
#   32    : The maximum length of a netmask (indicates single host subnet)
sub netmask_to_length {
    my $mask = (shift or 0);

    my $length = 32;

    while ( ($mask % 2) == 0 ){
        $mask>>=1;
        $length--;
    }

    return $length;
}

# Translate a number to a dotted quad
# XXX: Is there a module for this?
# Input:
#   Str      : The number to convert
# Output:
#   Str      : The converted number
#   OR
#   0.0.0.0  : Nothing or 0 was passed in
sub num_to_dot_quad {
    my $num = (shift || 0);
    my ( $first, $second, $third, $fourth );

    $first  = $num >> 24;
    $second = ($num >> 16) & 0xff;
    $third  = ($num >> 8) & 0xff;
    $fourth = $num & 0xff;

    return "$first.$second.$third.$fourth";
}

# Translate a dotted quad to a number
# XXX: Is there a module for this?
# Input:
#   Str: The dotted quad to convert
# Output:
#   Str: The converted quad
#   OR
#   0  : Nothing was passed in, so nothing was converted
sub dot_quad_to_num {
    my $quad = shift;

    my $num = 0;

    if ($quad =~ /([0-9]+\.?){4}/) {
        my ( $first, $second, $third, $fourth ) = split(/\./, $quad);

        $num = ( $first << 24 | $second << 16 | $third << 8 | $fourth );
    }

    return $num;
}

# Locate all subnets associated with every device on the machine
# Input:
#   N/A
# Ouput:
#   Array: The found subnets
#   OR
#   ()   : No subnets were found
sub enumerate_subnets {
    my @ifconfig = qx(ifconfig -a|grep inet);

    my ($addr, $mask);
    my @subnets = ();

    my $regexp = qr/.*inet (?:addr:)?([0-9.]+).*(?:Mask:|netmask )([0-9.]+)/o;

    LINE:
    for my $line (@ifconfig) {
        $line =~ /$regexp/;
        $addr = dot_quad_to_num($1||0);
        $mask = dot_quad_to_num($2||0);

        next LINE if (!$addr or !$mask or (($addr & 0xff000000) == 0x7f000000));

        push @subnets, num_to_dot_quad($addr & $mask)."/".netmask_to_length($mask);
    }

    return @subnets;
}

# Find the site name
# This will look up the site name for one of the subnets associated with the hosts NIC's
# XXX XXX: As far as I've been able to find out, we don't have subnet DN's or 'siteObject's
#          or 'siteName's, so I have no way of testing this code. I'm translating
#          this as best I can, but I make no promises on its veracity
# Input:
#   Str: The location of the Kerberos Ticket cache file
#   Str: The domain controller to connect to
# Output:
#   Str: The found site value
#   OR
#   '' : Nothing was found; the empty string is returned
sub find_site {
    my $ccname            = (shift || ''); # This should probably do something when it fails...
    my $domain_controller = (shift || ''); # This too

    my $site_name      = '';
    my $subnet_domain = '';
    my $ldapsrv       = '';

    my @results      = ();
    my @more_results = ();
    my $ldap_options = '-Q -Y gssapi -b "" -s sub';
    my $more_ldap_opts = '';

    $ccname = "KRB5CCNAME=$ccname";

    my @subnets = enumerate_subnets();
    SUBNET:
    for my $subnet (@subnets) {

        print "\tLooking for subnet object in the global catalog.\n";
        @results = qx($ccname ldapsearch -h $domain_controller $ldap_options cn=$subnet dn);

        LINE:
        for my $line (@results) {

            # This fixes $line, but if it doesn't match (i.e. we have a line
            # we don't want to use) it will skip to the next line
            next LINE unless ($line =~ s/^dn (.+)/$1/);

            print "\tLooking for subnet objects in its domain.\n";
            $subnet_domain = dn2dns($line);
            $ldapsrv = canon_resolve("DomainDnsZones.$subnet_domain");

            $more_ldap_opts = "-Q -Y gssapi -b \"$line\" -s base \"\" siteObject";
            @more_results = qx($ccname ldapsearch -h $ldapsrv $ldap_options);

            SITEDN:
            for my $line (@more_results) {

                # This fixes $line, but if it doesn't match (i.e. we have a line
                # we don't want to use) it will skip to the next line
                next SITEDN unless ($line =~ s/^siteObject CN=(.+),.*/$1/);

                # Found it; store it and exit the loops
                $site_name = $line;
                last SUBNET;
            }
        }
    }
    return $site_name;
}

# Find the forest name
# NOTE: I'm not sure if this is ever different from the '$domain' value passed in or discovered.
#       It would be really nice to know.
# Input:
#   Str: The location of the Kerberos Ticket cache file
#   Str: The domain controller to connect to
# Output:
#   Str: The found forest value
#   OR
#   '' : Nothing was found; the empty string is returned
sub find_forest {
    my $ccname            = (shift || ''); # This should probably do something when it fails...
    my $domain_controller = (shift || ''); # This too

    my $forest = '';
    my @results = ();

    my $ldap_options = '-Q -Y gssapi -b "" -s base "" schemaNamingContext';

    $ccname = "KRB5CCNAME=$ccname";

    @results = qx($ccname ldapsearch -h $domain_controller $ldap_options);

    for my $line (@results) {
        if ($line =~ /^schema/) {
            $line =~ s/^\w+: CN=\w+,CN=\w+,//;
            $forest = dn2dns($line);
        }
    }
    return $forest;
}

# Do a DNS search for the 'record' associated with 'name'
# TODO: Think about better incorporating the verbose variable (is it only for warnings,
#       or should it be for everything.
# Defaults:
#   'record' : 'A'
#   'verbose': ''
# Input:
#   Str   : The 'name' to search for
#   [Str] : The 'record' to search for
#   [Bool]: Whether to be verbose or not
# Output:
#   Array : Net::DNS::RR objects, one per answer
#   OR
#   ()    : The empty array, if nothing was found
sub dns_search {
    my $name = shift;
    my $record = (shift || 'A');
    my $verbose = (shift || '');

    my @results = ();

    my $query = Net::DNS::Resolver->new;
    my $response = $query->search($name, $record);

    if ($response) {
        @results = $response->answer;
    }
    else {
        if ($verbose) {
            warn "ERROR: Name \"$name\" does not resolve properly.\n";
            warn "ERROR: \tMake sure that you specify a valid host name;\n";
            warn "ERROR: \teither in short (when you have a list of domains\n";
            warn "ERROR: \tto search stored in your resolv.conf file) or as\n";
            warn "ERROR: \ta fully qualified domain name.\n";
        }
    }

    return @results;
}

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
    my $kpasspwd = (shift || '');
    my $realm    = (shift || '');
    my $template = (shift || 'adjoin-krb5.conf.XXXXXX');

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

# Returns the kpasswd servers defined in DNS
# Input:
#   Str: The domain we're searching for
# Output:
#   Array[Hash] : A list of hashes holding the name and port for the KPASSWD servers
#   OR
#   ()          : The empty list, if there aren't any such servers
sub enumerate_KPWs {
    my $domain = (shift || '');

    return get_SRVs("_kpasswd._tcp.$domain.");
}

# Return an array of hosts and port combos gleaned from SRV records
# XXX: Do I actually want a hash? Maybe I want a list of lists?
#       I think I want a list of hashes. Less magic numbers, more magic names
#       The downside to this is that you have to know there is a "name" and "port"
#       key in that hash. Is there a better way to do this?
# Input:
#   Str  : entry to search for
# Output:
#   Array[Hash]: The collection of SRV records found, an Array of Hashes
#   OR
#   ()       : Nothing was found
sub get_SRVs {
    my $name = shift;

    my @SRVs = ();

    my @results = dns_search($name, 'SRV');

    # TODO: I have temporarily skipped on incorporating the '$dnssrv' option
    # into this function, as I will probably have to rethink how to approach its
    # incorporation in every DNS query.

    for my $answer (@results) {
        if ($answer->type eq "SRV") {
            push(@SRVs,
                     { name => $answer->target,
                       port => $answer->port });
        }
    }

    return @SRVs;

}

# Find the Global Catalog servers
# Input:
#   Str: The forest we're searching in
#   Str: The sitename we're using TODO:XXX: What is this variable for?
# Output:
#   Array[Hash]: A list of hashes holding the name and port for the KDC's
#   OR
#   () : The empty list
sub enumerate_GCs {
    my $forest   = (shift || '');
    my $sitename = (shift || '');

    # Format '$sitename' for inclusion in the 'get_SRVs' function call, regardless
    # of it's contents (if it's empty, it stays empty)
    $sitename =~ s/(.+)/.$1._sites/;

    return get_SRVs("_ldap._tcp".$sitename.".gc._msdcs.$forest.");
}

# Find the Key Distribution Centers (KDCs)
# Input:
#   Str: The domain we're searching in
#   Str: The sitename we're using TODO:XXX: What is this variable for?
# Output:
#   Array[Hash]: A list of hashes holding the name and port for the KDC's
#   OR
#   () : The empty list
sub enumerate_KDCs {
    my $domain   = (shift || '');
    my $sitename = (shift || '');

    # Format '$sitename' for inclusion in the 'get_SRVs' function call, regardless
    # of it's contents (if it's empty, it stays empty)
    $sitename =~ s/(.+)/.$1._sites/;

    return get_SRVs("_kerberos._tcp".$sitename.".$domain.");
}

# TODO: enumerate_KDCs and enumerate_DCs are almost identical; I should figure out how to merge them.
# Find the Domain Controllers (DCs)
# Input:
#   Str: The Domain we're searching in
#   Str: The sitename we're using TODO:XXX: What is this variable for?
# Output:
#   Array[Hash]: A list of hashes holding the name and port for the DC's
#   OR
#   () : The empty list
sub enumerate_DCs {
    my $domain   = (shift || '');
    my $sitename = (shift || '');

    # Format '$sitename' for inclusion in the 'get_SRVs' function call, regardless
    # of it's contents (if it's empty, it stays empty)
    $sitename =~ s/(.+)/.$1._sites/;

    return get_SRVs("_ldap._tcp".$sitename.".dc._msdcs.$domain.");

}


# Convert an AD-style domain DN to a DNS domainname
# This will convert regardless of case.
# Input:
#   Str: The DN to convert
# Output:
#   Str: The converted DN
#   OR
#   '' : There was no DN to convert
sub dn2dns {
    my $dnDNS = '';

    my $DN = shift;

    if ($DN) {
        $DN =~ s/^DC=//i;
        $DN =~ s/,DC=/\./gi;
        $dnDNS = $DN;
    }

    return $dnDNS;
}

# Convert a DNS domainname to an AD-style DN for that domain
# Input:
#   Str: The domain name to convert
# Output:
#   Str: The converted domain name
#   OR
#   '' : There was no domain to convert
sub dns2dn {
    my $dnsDN = '';

    my $domainname = shift;

    if ($domainname) {
        $domainname =~ s/\./,DC=/g;
        $dnsDN = "DC=" . $domainname;
    }

    return $dnsDN;
}

# Form a base DN from a DNS domainname and container
# Input:
#   Str: 'container' holds the container to use
#   Str: 'domainname' holds the domainname to use
# Output:
#   Str: The 'baseDN' that was created
#   OR
#   '' : The empty string, because nothing was given or found
sub get_base_dn {
    my $baseDN = '';

    my $container  = '';
    my $domainname = '';

    my $dnsDN = '';

    if ($#ARGV == 1) {
        $container = (shift) . ",";
    }

    if ($#ARGV == 0) {
        $domainname = shift;
        $dnsDN      = dns2dn($domainname);
        $baseDN     = $container . $dnsDN;
    }

    return $baseDN;
}

# Find the canonical name for a domainname
# Input:
#   Str: The domain name to search for
# Ouput:
#   Str: The canonical FQDN for the domain
#   OR
#   '' : The empty string (if the input doesn't resolve to anything)
sub canon_resolve {
    my $name = shift;

    my $cname = '';

    my @results = dns_search($name, 'A');

    # As designated in RFC 1034, when we search for an 'A' record, if a 'CNAME' record
    # exists, we'll get both the 'CNAME' and the 'A' record(s) for the canonical name.
    # As such, we'll search for the 'CNAME' record and use it, but if not, then the 'A'
    # record returned will hold the canonical name for whatever we searched for.
    ANSWER:
        for my $answer (@results) {
            if ($answer->type eq "CNAME") {
                # Found it; save it and exit the loop
                $cname = $answer->cname;
                last ANSWER;
            }
            else {
                $cname = $answer->name;
            }
        }

    return $cname;
}

# Discover the domain
# Input:
#   N/A
# Output:
#   Str: The found domain (without the ending dot)
#   OR
#   '' : The empty string (nothing found)
sub discover_domain {
    my $query = Net::DNS::Resolver->new;
    my $response = $query->search('_ldap._tcp.dc._msdcs', 'SRV');

    my $domain = '';

    # Copy $response->string into $domain, then do a search/replace on $domain
    ($domain = $response->string) =~ s/.*_ldap._tcp.dc._msdcs.([\w.]+)\.\s.*/$1/s;
    return $domain;
}

# Check nsswitch.conf to make sure the hosts entry uses dns
# Input:
#   N/A
# Output:
#   Returns 1 for success and 0 for failure
sub check_nss_conf {
    open(my $nsswitch, "<$nssfile") or die("Can't open $nssfile: $!");
    for my $line (<$nsswitch>) {
        chomp($line);
        if ($line =~ /^hosts:.*\bdns\b.*/) {
            close($nsswitch);
            return(1);
        }
    }
    close($nsswitch);
    return(0);
}

# This is a really sub-par way to check for an ip address (any string of numbers works, f.e.)
# However! I'm not yet completely certain what purpose $dnssrv
# is supposed to fulfill, so once I understand that, I'll come back and fix this.
# TODO: See above paragraph.
#       I should look into ip_is_ipv{4,6} from Net::IP
sub check_dnssrv {
    my $tmp_dnssrv = shift;
    ($tmp_dnssrv =~ /[0-9.:, ]+/)
        && return(1)
        || return(0);
}

GetOptions(
   'help|h|?'      => \$help,
   'man'           => \$man,
   'dc|d=s'        => \$domain_controller,
   'dnssrv|D=s'    => \$dnssrv,
   'cprinc|p=s'    => \$cprinc,
   'site|s=s'      => \$site,
   'ignore|i'      => sub { $ignore_existing=1; $modify_existing=0; },
   'dryrun|n!'     => \$dryrun,
   'debug|x!'      => \$debug,
   'verbose|v!'    => \$verbose,
   'container|o=s' => \$container,
   'reset|r'       => sub { $add_account=0; $force=0;
                            $extra_force=0; $modify_existing=1; },
    )
    or pod2usage(2);

pod2usage(1) if $help;
pod2usage(-exitstatus => 0, -verbose => 2) if $man;

# Make sure we have a proper dnssrv listing
check_dnssrv($dnssrv) || pod2usage(2);

if ($#ARGV >= 2) {
    print "Too many things specified on the command line.\n";
    pod2usage(2);
}
elsif ($#ARGV >= 0) {
    $domain = $ARGV[0];
    if ($#ARGV >= 1) {
        $nodename = $ARGV[1];
    }
}
else {
    $domain = discover_domain();
    if ($domain) {
        print "Joining domain: $domain\n";
    }
    else {
        print "No domain was specified and one could not be discovered.\n";
        print "Please check your DNS resolver configuration\n";
        exit(1);
    }
}

if (!$cprinc){
    print "Please specify the administrative principal to use: ";
    chomp($cprinc = <STDIN>);
}

check_nss_conf() or die "$nssfile does not use dns for hosts, which it (probably) should.\n";

$upcase_nodename  = uc($nodename);
$netbios_nodename = "$nodename\$";
# This is probably wrong. What about a machine that's foo.cs.umn.edu and the domain
# it should join is COSE.UMN.EDU? A bit unorthodox perhaps, but possible.
# TODO: Investigate this possibility.
# XXX: There is a possibility fqdn should be put together like the following. I /really/ doubt
#       it, and assume, instead, that the original implementation was either flawed, or did not
#       account for a machine with a different domain than the domain it's joining. This should
#       be verified and, if true, remove this comment block.
#$fqdn = "$nodename.$dom";

print "Looking for domain controllers and global catalogs (A RRs)\n";
$DomainDnsZones = canon_resolve("DomainDnsZones.$domain.");
$ForestDnsZones = canon_resolve("ForestDnsZones.$domain.");

$realm = uc($domain);

$baseDN = get_base_dn($container, $domain);

print "Looking for KDCs and DCs (SRV RRs)\n";
@KDClist = enumerate_KDCs($domain);
if (!@KDClist){
    # XXX: What if '$DomainDnsZones' is empty? Same for '$ForestDnsZones'
    @KDClist = ({ name => $DomainDnsZones, port => 88 });
    $kdc     = $ForestDnsZones;
}
else {
    $kdc     = $KDClist[0]->{name};
}

@DClist = enumerate_DCs($domain);
if (!@DClist) {
    # XXX: What if '$DomainDnsZones' is empty?
    @DClist            = ({ name => $DomainDnsZones, port => 389 });
    $domain_controller = $DomainDnsZones;
}
else {
    $domain_controller = $DClist[0]->{name};
}

@KPWlist = enumerate_KPWs($domain);
if (!@KPWlist) {
    # TODO: Make a function to test the @KDClist servers, using port 464, to find a server
    #       that works. I should use Net::Ping, methinks.
    warn "We can't find a kpasswd server in DNS, so we're assuming the KDC works.\n";
    warn "This is probably wrong.\n";
    $kpasswd = $kdc;
}
else {
    $kpasswd = $KPWlist[0]->{name};
}

# TODO: These loops could be in a function
print "\nKDCs\n----";
for my $pair (@KDClist) {
    print "\nName: ${$pair}{name}\nPort: ${$pair}{port}\n";
}
print "\nDCs\n----";
for my $pair (@DClist) {
    print "\nName: ${$pair}{name}\nPort: ${$pair}{port}\n";
}
print "\nkpasswd servers\n----";
for my $pair (@KPWlist) {
    print "\nName: ${$pair}{name}\nPort: ${$pair}{port}\n";
}

$krb5conf = construct_krb5_conf(\@KDClist, $kpasswd, $realm);
(undef, $krb5ccname) = tempfile($cname_template, DIR => '/tmp', OPEN => 0);
(undef, $new_keytab) = tempfile($keytab_template, DIR => '/tmp', OPEN => 0);

print "Getting initial credentials via 'kinit'.\n";
system("kinit $cprinc -c $krb5ccname") == 0
    or die "system call to 'kinit' failed, can't continue. Error code: $?";
print "Credentials cached in $krb5ccname\n";

print "Looking for forest name.\n";
$forest = find_forest( $krb5ccname, $domain_controller );
if ($forest) {
    print "Forest name = $forest\n";
}
else {
    warn "ERROR: Forest name not found.\n";
    warn "ERROR: Assuming the forest name is the same as the domain, \"$domain\".\n";
    $forest = $domain;
}

print "Looking for Global Catalog servers (SRV RRs).\n";
@GClist = enumerate_GCs($forest) unless $global_catalog;
if (!@GClist){
    @GClist         = ({ name => $ForestDnsZones, port => 3268 });
    $global_catalog = $ForestDnsZones;
}
else {
    $global_catalog = $GClist[0]->{name};
}

print "Looking for site name.\n";
$site_name = find_site( $krb5ccname, $domain_controller );

if (!$site_name) {
    print "\tSite name not found. Local DCs/GCs will not be discovered.\n";
}
else {
    print "Looking for local KDCs, DCs and global catalog servers (SRV RRs).\n";
    # TODO: This is duplicated, almost entirely, from above. That should be fixed some how
    #       (while loop?)
    @KDClist = enumerate_KDCs($domain, $site_name);
    if (!@KDClist){
        # XXX: What if '$DomainDnsZones' is empty? Same for '$ForestDnsZones'
        @KDClist = ({ name => $DomainDnsZones, port => 88 });
        $kdc     = $ForestDnsZones;
    }
    else {
        $kdc     = $KDClist[0]->{name};
    }

    @DClist = enumerate_DCs($domain, $site_name);
    if (!@DClist) {
        # XXX: What if '$DomainDnsZones' is empty?
        @DClist            = ({ name => $DomainDnsZones, port => 389 });
        $domain_controller = $DomainDnsZones;
    }
    else {
        $domain_controller = $DClist[0]->{name};
    }

    @GClist = enumerate_GCs($forest) unless $global_catalog;
    if (!@GClist){
        @GClist         = ({ name => $ForestDnsZones, port => 3268 });
        $global_catalog = $ForestDnsZones;
    }
    else {
        $global_catalog = $GClist[0]->{name};
    }

    # TODO: These loops could be in a function
    print "\nLocal KDCs\n----";
    for my $pair (@KDClist) {
        print "\nName: ${$pair}{name}\nPort: ${$pair}{port}\n";
    }
    print "\nLocal DCs\n----";
    for my $pair (@DClist) {
        print "\nName: ${$pair}{name}\nPort: ${$pair}{port}\n";
    }
    print "\nLocal GCs\n----";
    for my $pair (@GClist) {
        print "\nName: ${$pair}{name}\nPort: ${$pair}{port}\n";
    }
}

if (!@GClist) {
    warn "Couldn't find any global catalogs. Exiting.\n";
    exit 1;
}

# XXX bad times below
sleuth_machine_bad_times( $baseDN, $netbios_nodename, $krb5ccname,
                          $domain_controller, $ignore_existing, $modify_existing,
                          $extra_force, $leave, $verbose );
__END__

=head1 NAME

adjoin - Join or Disjoin a computer from the domain.

=head1 SYNOPSIS

Usage: adjoin  [options] [domain [nodename]]
Usage: adleave [options] [domain [nodename]]

Joins or leaves an Active Directory domain.  This includes:

 o deleting a Computer object in AD
 o creating a Computer object in AD
 o setting its password to a randomized password
 o creating /etc/krb5/krb5.conf
 o creating /etc/krb5/krb5.keytab with keys based on the
   computer password

The administrator MUST make sure that:

 - /etc/resolv.conf is setup properly, which, if the AD domain
   has not been delegated, means:

	+ only nameservers for that domain must be used in resolv.conf

   Creating a useful search list is recommended.

 - /etc/nsswitch.conf says "files dns" for 'hosts' and 'ipnodes'.

Options:

 -h	This message

 -n	Dry-run (don't do anything)
 -v	Verbose (show the commands run and objects created/modified)

 -i	Ignore any pre-existing computer account for this host;
	change its keys.
 -r	Reset  any pre-existing computer account for this host
	and change its keys.
 -f	Delete any pre-existing computer account for this host.
 -f -f	Delete any pre-existing computer account for this host
	and objects contained by it.

 -d ...	Name of a domain controller to use.  If not given one
	will be found.  Note: this MUST be a domain controller
	in the domain being joined and it MUST also be a global
	catalog server [Default: discover one]
 -p ...	Name of an administrator principal to use for creating
	the computer account [default: Administrator]
 -D Set the DNS server to use

Other options:

 -o ... Container where to put machine account [Default: CN=Computers]
 -x	Debug

TODO:

Examples:

	./adjoin.pl -p joe.admin example.com

=cut
# vim: ts=4 sw=4 et fdm=syntax
