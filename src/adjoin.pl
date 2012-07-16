#!/soft/perl/bin/perl

use strict;
use warnings;

use Carp;
use Getopt::Long;
use Pod::Usage;
use English;
use Net::Domain qw(hostname hostfqdn hostdomain);
use Net::DNS;

my $option_results;

# Defaults
my $container="CN=Computers";
my $cprinc="Administrator";
my $fqdn=hostfqdn();
my $ldap_args="-o authzid= -o mech=gssapi";
my $nodename=hostname();
my $nssfile="/etc/nsswitch.conf";
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
my $dc='';
my $dnssrv='';
my $domain='';
my $domain_controller='';
my $DomainDnsZones='';
my $ForestDnsZones='';
my $kdc='';
my $netbios_nodename='';
my $realm='';
my $site=''; # This variable is never used in adjoin.sh
my $upcase_nodename='';

if ($PROGRAM_NAME eq "adleave"){
    $leave=1;
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
#   Array : Net::DNS::Packet objects, one per answer
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

# Return an array of hosts and port combos gleaned from SRV records
# XXX: Do I actually want a hash?
# Input:
#   Str  : entry to search for
# Output:
#   Array: The collection of SRV records found
#   OR
#   ()   : Nothing was found
sub getSRVs {
    my $name = shift;

    my @answers = ();

    # TODO: I have temporarily skipped on incorporating the '$dnssrv' option
    # into this function, as I will probably have to rethink how to approach its
    # incorporation in every DNS query.

    # TODO: I find I'm doing this a lot, in different functions. I should figure out how to make this
    # less replicated
    my $query = Net::DNS::Resolver->new;
    my $response = $query->search($name, 'SRV');

    if (!$response) {
        warn "ERROR: FQDN \"$name\" does not resolve properly.\n";
        warn "ERROR: \tMake sure that you specify a valid host name;\n";
        warn "ERROR: \teither in short (when you have a list of domains\n";
        warn "ERROR: \tto search stored in your resolv.conf file) or as\n";
        warn "ERROR: \ta fully qualified domain name.\n";
        return '';
    }
}

# Find the Key Distribution Center (KDC)
# Input:
#   N/A
# Output:
#   Str: The found KDC
sub getKDC {
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
sub check_dnssrv {
    my $tmp_dnssrv = shift;
    ($tmp_dnssrv =~ /[0-9.:, ]+/)
        && return(1)
        || return(0);
}

GetOptions(
   'help|h|?'      => \$help,
   'man'           => \$man,
   'dc|d=s'        => \$dc,
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

print "Looking for KDCs and DCs (SRV RRs)";
$kdc = getKDC();

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

Other options:

 -o ... Container where to put machine account [Default: CN=Computers]
 -x	Debug

TODO:
 -D TODO: This does something, but I'm not sure what yet.

Examples:

	./adjoin.pl -p joe.admin example.com

=cut
# vim: ts=4 sw=4 et fdm=syntax
