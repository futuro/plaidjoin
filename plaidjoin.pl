#!/usr/bin/perl
# This is the PerL Automated Interactive Domain JOINer
# Copyright (C) 2012 Futuro (Evan Niessen-Derry)

# Author: Futuro (Evan Niessen-Derry) <evan @t cs dot umn dot edu>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;

use sigtrap qw(die INT QUIT);

use English;

use FindBin qw($Bin);

use Getopt::Long;
use Pod::Usage;

use Net::Domain qw(hostname hostfqdn hostdomain);

use lib "$Bin/lib";
use DNS;
use Kerberos;
use Encryption;
use Files;
use LDAP;

# TODO: Have these replace the scalar variables below
use constant {
    ACCOUNTDISABLE            => 2,
    PASSWD_NOTREQD            => 32,
    WORKSTATION_TRUST_ACCOUNT => 4096,
    DONT_EXPIRE_PASSWD        => 65536,
    TRUSTED_FOR_DELEGATION    => 524288,
};

my $option_results;

# GLOBALS
my $ACCOUNTDISABLE = 2;
my $PASSWD_NOTREQD = 32;
my $WORKSTATION_TRUST_ACCOUNT = 4096;
my $DONT_EXPIRE_PASSWD = 65536;
my $TRUSTED_FOR_DELEGATION = 524288;

# Defaults
my $cname_template="plaidjoin-krb5ccache.XXXXXX";
my $container="CN=Computers";
my $cprinc="Administrator";
my $encrypt_template="plaidjoin-encryption-object.XXXXXX";
my $fqdn=hostfqdn();
my $keytab_template="plaidjoin-krb5keytab.XXXXXX";
my $kvno=1;
my $minlower = 15;
my $minnum = 15;
my $minspecial = 15;
my $minupper = 15;
my $nodename=hostname();
my $nssfile="/etc/nsswitch.conf";
my $object_template="plaidjoin-computer-object.XXXXXX";
my $passlen = 80;
my $port=3268;
my $userAccountControlBASE = $WORKSTATION_TRUST_ACCOUNT;

# Bools
my $help='';
my $man='';

my $debug='';
my $dryrun=''; # TODO: There should be a wrapper function to enable dryrun functions
my $extra_force='';
my $force='';
my $ignore_existing='';
my $leave_domain='';
my $modify_existing='';
my $verbose='';

my $add_account="1";
my $join="1";
my $setup_config="1";

# Placeholder vars
my $baseDN='';
my @DClist=();
my $dnssrv='';
my $domain='';
my $domain_controller='';
my $DomainDnsZones='';
my @enc_types=();
my $escaped_machine_passwd='';
my $forest='';
my $ForestDnsZones='';
my $global_catalog='';
my @GClist=();
my $kdc='';
my @KDClist=();
my $keytab_file='';
my $kpasswd='';
my @KPWlist=();
my $krb5ccname='';
my $krb5conf='';
my $ldap='';
my $machine_passwd='';
my $netbios_nodename='';
my $object_file='';
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
        unlink $krb5ccname                   if $krb5ccname;
    }
    $ldap->unbind unless !$ldap;

    $? = $exitval;
}

if ($PROGRAM_NAME eq "plaidpart"){
    $leave_domain=1;
}

# Finalize the machine account
sub finalize_machine_account {
    my $ldap               = (shift or '');
    my $upcase_nodename    = (shift or '');
    my $baseDN             = (shift or '');
    my $userAccountControl = (shift or 0);
    my $dryrun             = (shift or 0);

    $userAccountControl += ($TRUSTED_FOR_DELEGATION + $DONT_EXPIRE_PASSWD);

    print "Finalizing machine account.\n";

    ldapreplace($ldap, "CN=$upcase_nodename,$baseDN", { userAccountControl => $userAccountControl })
        unless $dryrun;
}

# Deduce the new principal's key version number
# TODO: Fill out this header format
# Input:
#   St
sub deduce_kvno {
    my $ldap              = (shift or '');
    my $baseDN            = (shift or '');
    my $upcase_nodename   = (shift or '');

    my $kvno = 1;

    my $result = ldapsearch($ldap, $baseDN, 'sub', "cn=$upcase_nodename", ["msDS-KeyVersionNumber"]);

    foreach my $entry ($result->entries) {
        next unless ($kvno = $entry->get_value('msDS-KeyVersionNumber'));

        last;
    }
    chomp $kvno;

    return $kvno;
}

# Creates and adds the ldap machine account
# Input:
#   Str : The uppercased node name
#   Str : The base distinct name
#   Str : The netbios nodename
#   Str : The realm
#   Num : The UAC Base number
#   Bool: Whether to modify existing accounts
#   Bool: Whether to ignore existing accounts
# Output:
#   N/A
sub create_ldap_account {
    my $upcase_nodename        = (shift or '');
    my $baseDN                 = (shift or '');
    my $netbios_nodename       = (shift or '');
    my $realm                  = (shift or '');
    my $userAccountControlBASE = (shift or 0);
    my $modify_existing        = (shift or '');
    my $ignore_existing        = (shift or '');

    my $fqdn = hostfqdn();
    my $userAccountControl = ($userAccountControlBASE + $PASSWD_NOTREQD + $ACCOUNTDISABLE);
    my $userPrincipalName = $fqdn."@".$realm;

    my $result;

    my $distinguished_name = "CN=$upcase_nodename,$baseDN";

    if ($modify_existing) {
        print "A machine account already exists; resetting it.\n";
        $result = ldapreplace( $ldap, $distinguished_name,
                                {
                                  servicePrincipalName => "host/$fqdn",
                                  userAccountControl   => $userAccountControl,
                                  dNSHostname          => $fqdn,
                                }
                             );
        $result->code and warn "Failed to replace entry servicePrincipalName: ", $result->error;

    }
    elsif ($ignore_existing) {
        print "A machine account exists; re-using it.\n";
    }
    else {
        print "Creating the machine account in AD via LDAP.\n";

        $result = ldapadd( $ldap, $distinguished_name,
                            {
                                objectClass          => "computer",
                                cn                   => $upcase_nodename,
                                sAMAccountName       => $netbios_nodename,
                                userPrincipalName    => "host/$userPrincipalName",
                                servicePrincipalName => "host/$fqdn",
                                userAccountControl   => $userAccountControl,
                                dNSHostname          => $fqdn,
                            }
                        );
        $result->code and die "Failed to add new object to AD: $!", $result->error;
    }
}

# Deduce whether there is an existing machine account and do something (or don't) about it.
# Input:
#   Scalar: The LDAP object to use for ldap operations
#   Scalar: The base distinguished name to base off of
#   Scalar: The netbios nodename for the machine
#   Scalar: Whether we're ignoring existing objects
#   Scalar: Whether we're modifying existing objects
#   Scalar: Whether we're parting the domain
# Output
#   N/A
sub handle_preexisting_object {
    my $ldap            = (shift or '');
    my $baseDN          = (shift or '');
    my $upcase_nodename = (shift or '');
    my $ignore_existing = (shift or 0);
    my $modify_existing = (shift or 0);
    my $leave_domain    = (shift or 0);

    my $distinguished_name;
    my $result;

    print "Checking for pre-existing machine account.\n";

    if ($dryrun) {
        print "In a dry-run, no work done.\n";
        return 1;
    }

    $result = ldapsearch( $ldap, $baseDN, 'sub', "cn=$upcase_nodename", ['dn'] );
    $distinguished_name = $result->entry(0)->dn if $result->entry(0);

    if ($distinguished_name and !$ignore_existing) {
        if ($modify_existing and ($force or $leave_domain)) {
            print "Deleting existing machine account.\n";
            # TODO Something should happen if ldapdelete fails
            ldapdelete( $ldap, $distinguished_name );
        }
        else {
            warn "A machine account already exists. Try -i, -r or -f (see usage). Quitting.\n";
            exit 1;
        }
    }

    if ($leave_domain) {
        my $base = ($0 =~ m|\./(.*)+|);
        print "Machine succesfully parted from domain.\n";
        print "$base: Done\n";
        exit 0;
    }
}

# Find the site name
# This will look up the site name for one of the subnets associated with the hosts NIC's
# XXX XXX: As far as I've been able to find out, we don't have subnet DN's or 'siteObject's
#          or 'siteName's, so I have no way of testing this code. I'm translating
#          this as best I can, but I make no promises on its veracity
# Input:
#   Scalar: The LDAP object to search with
# Output:
#   Str: The found site value
#   OR
#   '' : Nothing was found; the empty string is returned
sub find_site {
    my $ldap = (shift or '');

    my $site_name;
    my $subnet_domain;
    my $ldapsrv;
    my $site_ldap;

    my $result;
    my $site_result;

    print "\tLooking for subnet objects in the global catalog.\n";
    my @subnets = enumerate_subnets();
    SUBNET:
    for my $subnet (@subnets) {
        print "\tLooking for subnet objects in its domain.\n";

        $result = ldapsearch( $ldap, '', 'sub', "cn=$subnet", ['dn'] );
        ENTRY:
        foreach my $entry ($result->entries) {
            $subnet_domain = dn_to_dns($entry->dn);
            next ENTRY unless ($ldapsrv = canonical_resolve("DomainDnsZones.$subnet_domain"));

            $site_ldap = gen_ldap_bind( $ldapsrv );
            $site_result = ldapsearch( $site_ldap, $entry->dn, 'base', undef, ['siteObject'] );
            $site_ldap->unbind;

            SITEDN:
            foreach my $site_entry ($site_result->entries) {

                $site_name = $site_entry->get_value( "siteObject" );
                next SITEDN unless ($site_name =~ s/CN=(.+),.*/$1/);

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
#   Scalar: The LDAP object to use for LDAP operations
# Output:
#   Str: The found forest value
#   OR
#   '' : Nothing was found; the empty string is returned
sub find_forest {
    my $ldap = (shift or '');

    my $forest = '';
    my $result;

    $result = ldapsearch( $ldap, undef, 'base', undef, ['schemaNamingContext'] );
    foreach my $entry ($result->entries) {
        my $naming_context = ($entry->get_value("schemaNamingContext") =~ /^CN=\w+,CN=\w+,(.*)/);
        $forest = dn_to_dns( $naming_context );
        last;
    }

    return $forest;
}

# Check nsswitch.conf to make sure the hosts entry uses dns
# Input:
#   N/A
# Output:
#   Returns 1 for success and 0 for failure
sub validate_nss_conf {
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
    $domain = deduce_domain();
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

validate_nss_conf() or die "$nssfile does not use dns for hosts, which it (probably) should.\n";

$upcase_nodename  = uc($nodename);
$netbios_nodename = "$nodename\$";
$fqdn = hostfqdn();

print "Looking for domain controllers and global catalogs (A RRs)\n";
$DomainDnsZones = canonical_resolve("DomainDnsZones.$domain.");
$ForestDnsZones = canonical_resolve("ForestDnsZones.$domain.");

$realm = uc($domain);

$baseDN = get_base_dn($domain, $container);

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

$krb5conf = construct_krb5_conf(\@KDClist, $kpasswd, $domain, $realm);
$krb5ccname = generate_tmpfile($cname_template);
$keytab_file = generate_tmpfile($keytab_template);


print "Setting project credentials cache to '$krb5ccname'\n";
$ENV{KRB5CCNAME} = $krb5ccname;

print "Getting initial credentials via 'kinit'.\n";
kinit( $cprinc, $krb5ccname )
    or die "kinit failed, can't continue: $!";
print "Credentials cached in $krb5ccname\n";

$ldap = gen_ldap_bind( $domain_controller );

print "Looking for forest name.\n";
$forest = find_forest( $ldap );
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
$site_name = find_site( $ldap );

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

handle_preexisting_object( $ldap, $baseDN, $upcase_nodename,
                          $ignore_existing, $modify_existing,
                          $leave_domain, );

$object_file = generate_tmpfile($object_template);

create_ldap_account( $upcase_nodename, $baseDN,
                     $netbios_nodename, $realm, $userAccountControlBASE,
                     $modify_existing, $ignore_existing );

$machine_passwd = generate_and_set_passwd( $realm, $dryrun,
                                           $passlen, $minnum, $minlower, $minupper, $minspecial );

print "Finding Key Version Number.\n";
if (!$dryrun) {
    $kvno = deduce_kvno( $ldap, $baseDN, $upcase_nodename, );
    print "KVNO: $kvno\n";
}
else {
    print "Dryrun: assuming KVNO is default '$kvno'\n";
}

print "Finding the supported encryption types.\n";
@enc_types = deduce_and_set_enc_types( $ldap, $upcase_nodename, $baseDN, $dryrun );

finalize_machine_account( $ldap, $upcase_nodename, $baseDN, $userAccountControlBASE, $dryrun );

kt_write( $machine_passwd, $fqdn, $realm, $kvno, $keytab_file, );

if ($setup_config) {
    setup_krb_files( $krb5conf, $keytab_file, $dryrun );
}
else {
    print <<EOF;
We're not setting up the configuration files.
The kerberos config file can be found at "$krb5conf".
The keytab can be found at "$keytab_file".
Fiddle with and install as necessary.
EOF
}

print "The machine is now joined to the domain, rejoice!\n";

exit 0;

__END__

=head1 NAME

plaidjoin - Join or Disjoin a computer from the domain.

=head1 SYNOPSIS

Usage: plaidjoin  [options] [domain [nodename]]
Usage: plaidpart [options] [domain [nodename]]

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

	./plaidjoin.pl -p joe.admin example.com

=cut
# vim: ts=4 sw=4 et fdm=syntax
