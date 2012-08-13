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

use Carp;
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

my $option_results;

# Defaults
my $cname_template="plaidjoin-krb5ccache.XXXXXX";
my $container="CN=Computers";
my $cprinc="Administrator";
my $encrypt_template="plaidjoin-encryption-object.XXXXXX";
my $fqdn=hostfqdn();
my $keytab_template="plaidjoin-krb5keytab.XXXXXX";
my $kvno=1;
my $ldap_args="-o authzid= -o mech=gssapi"; # TODO: Verify these are actually correct
my $minlower = 15;
my $minnum = 15;
my $minspecial = 15;
my $minupper = 15;
my $nodename=hostname();
my $nssfile="/etc/nsswitch.conf";
my $object_template="plaidjoin-computer-object.XXXXXX";
my $passlen = 80;
my $port=3268;
my $userAccountControlBASE=4096;

# Bools
my $help='';
my $man='';

my $debug='';
my $dryrun=''; # TODO: There should be a wrapper function to enable dryrun functions
my $extra_force='';
my $force='';
my $ignore_existing='';
my $leave='';
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
        system("rm -f $krb5ccname")          if $krb5ccname;
    }
    $? = $exitval;
}

if ($PROGRAM_NAME eq "plaidleave"){
    $leave=1;
}

# Finalize the machine account
sub finalize_machine_account {
    my $upcase_nodename    = (shift or '');
    my $baseDN             = (shift or '');
    my $krb5ccname         = (shift or '');
    my $userAccountControl = (shift or 0);
    my $domain_controller  = (shift or '');
    my $dryrun             = (shift or 0);
    my $object_file        = (shift or generate_tmpfile("final_machine_obj.XXXXXX"));

    my $object;

    my @enc_types;

    # TODO: I should really document what these numbers mean...
    $userAccountControl += (524288 + 65536);

    my $ldap_options = qq(-Q -Y gssapi);
    $krb5ccname = "KRB5CCNAME=$krb5ccname" unless !$krb5ccname;

    print "Finding the supported encryption types.\n";
    @enc_types = deduce_and_set_enc_types( $upcase_nodename, $baseDN, $krb5ccname,
                                   $domain_controller, $dryrun );

    if (grep !/arcfour/, @enc_types) {
        $userAccountControl += 2097152;
    }

    print "Finalizing machine account.\n";

    $object = <<ENDOBJECT;
dn: CN=$upcase_nodename,$baseDN
changetype: modify
replace: userAccountControl
userAccountControl: $userAccountControl
ENDOBJECT

    open FH, ">$object_file" or die "Couldn't open $object_file: $!";
    print FH $object;
    close FH;

    if (!$dryrun) {
        system(qq($krb5ccname ldapmodify -h "$domain_controller" $ldap_options -f "$object_file"));
    }
}

# Deduce the new principal's key version number
# TODO: Fill out this header format
# Input:
#   St
sub deduce_kvno {
    my $domain_controller = (shift or '');
    my $baseDN            = (shift or '');
    my $upcase_nodename   = (shift or '');
    my $krb5ccname        = (shift or '');

    my $kvno = 1;

    my $ldap_options = qq(-Q -Y gssapi -b "$baseDN" -s sub "cn=$upcase_nodename" msDS-KeyVersionNumber);
    $krb5ccname = "KRB5CCNAME=$krb5ccname" unless !$krb5ccname;
    my @results = qx($krb5ccname ldapsearch -h $domain_controller $ldap_options);

    foreach my $line (@results) {
        next unless (($kvno = $line) =~ s/^msDS-KeyVersionNumber: (.+)/$1/);

        last;
    }

    chomp $kvno;

    return $kvno;
}

# Creates and adds the ldap machine account
# Input:
#   Str : The ldapadd object file name
#   Str : The uppercased node name
#   Str : The base distinct name
#   Str : The netbios nodename
#   Str : The realm
#   Str : The file name for the kerberos ticket cache
#   Num : The UAC Base number
#   Bool: Whether to modify existing accounts
#   Bool: Whether to ignore existing accounts
# Output:
#   N/A
sub create_ldap_account {
    my $object_file            = (shift or generate_tmpfile("ldap_obj.XXXXXX"));
    my $upcase_nodename        = (shift or '');
    my $baseDN                 = (shift or '');
    my $netbios_nodename       = (shift or '');
    my $realm                  = (shift or '');
    my $krb5ccname             = (shift or '');
    my $userAccountControlBASE = (shift or 0);
    my $domain_controller      = (shift or '');
    my $modify_existing        = (shift or '');
    my $ignore_existing        = (shift or '');

    my $fqdn = hostfqdn();
    my $userAccountControl = ($userAccountControlBASE + 32 + 2);
    my $userPrincipalName = $fqdn."@".$realm;

    my $ldap_options = qq(-Q -Y gssapi);
    my $object;

    $krb5ccname = "KRB5CCNAME=$krb5ccname" unless !$krb5ccname;

    if ($modify_existing) {
        $object = <<ENDOBJECT;
dn: CN=$upcase_nodename,$baseDN
changetype: modify
replace: servicePrincipalName
servicePrincipalName: host/$fqdn
-
replace: userAccountControl
userAccountControl: $userAccountControl
-
replace: dNSHostname
dNSHostname: $fqdn
ENDOBJECT

        open FH, ">$object_file" or die "Couldn't open $object_file: $!";
        print FH $object;
        close FH;

        print "A machine account already exists; resetting it.\n";
        system(qq($krb5ccname ldapadd -h $domain_controller $ldap_options -f "$object_file")) == 0
            or die "Could not add the new object to AD: $!";
    }
    elsif ($ignore_existing) {
        print "A machine account exists; re-using it.\n";
    }
    else {
        $object = <<ENDOBJECT;
dn: CN=$upcase_nodename,$baseDN
objectClass: computer
cn: $upcase_nodename
sAMAccountName: $netbios_nodename
userPrincipalName: host/$userPrincipalName
servicePrincipalName: host/$fqdn
userAccountControl: $userAccountControl
dNSHostname: $fqdn
ENDOBJECT

        open FH, ">$object_file" or die "Couldn't open $object_file: $!";
        print FH $object;
        close FH;

        print "Creating the machine account in AD via LDAP.\n";

        system(qq($krb5ccname ldapadd -h $domain_controller $ldap_options -f "$object_file")) == 0
            or die "Could not add the new object to AD: $!";
    }
}

# Do some OpenSolaris configuration stuff
# XXX XXX: I don't have access to an OpenSolaris box, so I make no assurances that this
#          code works, or does anything, or doesn't do every possible bad thing.
#          Use at your own risk.
# Input:
#   N/A
# Output:
#   1: Success (always)
sub correct_idmap {
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
    my $krb5ccname        = (shift or '');
    my $domain_controller = (shift or '');
    my $ignore_existing   = (shift or 0);
    my $modify_existing   = (shift or 0);
    my $extra_force       = (shift or 0);
    my $leave             = (shift or 0);
    my $verbose           = (shift or 0);

    $krb5ccname = "KRB5CCNAME=$krb5ccname" unless !$krb5ccname;

    my $distinct_name = '';

    my $ldap_options = '';
    my @results = ();

    if (!$dryrun) {
        print "Checking for an existing account.\n";
        $ldap_options = qq(-Q -Y gssapi -b "$baseDN" -s sub sAMAccountName="$netbios_nodename" dn);
        @results = qx($krb5ccname ldapsearch -h $domain_controller $ldap_options);

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
        @results = qx($krb5ccname ldapsearch -h $domain_controller $ldap_options);
        for my $answer (@results) {
            next unless (($answer =~ s/^dn: (.+)/$1/) and ($distinct_name ne $answer));

            $answer =~ /$distinct_name(.*)/;
            my $sub_dn = $1;

            if ($extra_force) {
                print "Deleting the following object: $sub_dn\n";
                system(qq($krb5ccname ldapdelete -h "$domain_controller" $ldap_options "$answer"));
            }
            else {
                print "The following object must be deleted (use -f -f, -r or -i): $sub_dn\n";
            }
        }

        if ($force or $leave) {
            print "Deleting existing machine account.\n";
            system(qq($krb5ccname ldapdelete -h "$domain_controller" $ldap_options "$distinct_name"));
        }
        elsif (!$modify_existing or !$ignore_existing) {
            warn "A machine account already exists. Try -i, -r or -f (see usage). Quitting.\n";
            exit 1;
        }
    }

    if ($leave) {
        correct_idmap(); # This is specifically for SNV/OpenSolaris
        my $base = ($0 =~ m|\./(.*)+|);
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
#   Str: The location of the Kerberos Ticket cache file
#   Str: The domain controller to connect to
# Output:
#   Str: The found site value
#   OR
#   '' : Nothing was found; the empty string is returned
sub find_site {
    my $krb5ccname        = (shift || ''); # This should probably do something when it fails...
    my $domain_controller = (shift || ''); # This too

    my $site_name      = '';
    my $subnet_domain = '';
    my $ldapsrv       = '';

    my @results      = ();
    my @more_results = ();
    my $ldap_options = '-Q -Y gssapi -b "" -s sub';
    my $more_ldap_opts = '';

    $krb5ccname = "KRB5CCNAME=$krb5ccname" unless !$krb5ccname;

    my @subnets = enumerate_subnets();
    SUBNET:
    for my $subnet (@subnets) {

        print "\tLooking for subnet object in the global catalog.\n";
        @results = qx($krb5ccname ldapsearch -h $domain_controller $ldap_options cn=$subnet dn);

        LINE:
        for my $line (@results) {

            # This fixes $line, but if it doesn't match (i.e. we have a line
            # we don't want to use) it will skip to the next line
            next LINE unless ($line =~ s/^dn (.+)/$1/);

            print "\tLooking for subnet objects in its domain.\n";
            $subnet_domain = dn_to_dns($line);
            $ldapsrv = canonical_resolve("DomainDnsZones.$subnet_domain");

            $more_ldap_opts = "-Q -Y gssapi -b \"$line\" -s base \"\" siteObject";
            @more_results = qx($krb5ccname ldapsearch -h $ldapsrv $ldap_options);

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
    my $krb5ccname        = (shift || ''); # This should probably do something when it fails...
    my $domain_controller = (shift || ''); # This too

    my $forest = '';
    my @results = ();

    my $ldap_options = '-Q -Y gssapi -b "" -s base "" schemaNamingContext';
    $krb5ccname = "KRB5CCNAME=$krb5ccname" unless !$krb5ccname;
    @results = qx($krb5ccname ldapsearch -h $domain_controller $ldap_options);

    for my $line (@results) {
        if ($line =~ /^schema/) {
            $line =~ s/^\w+: CN=\w+,CN=\w+,//;
            $forest = dn_to_dns($line);
        }
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

$object_file = generate_tmpfile($object_template);

create_ldap_account( $object_file, $upcase_nodename, $baseDN,
                     $netbios_nodename, $realm, $krb5ccname, $userAccountControlBASE,
                     $domain_controller, $modify_existing, $ignore_existing );

$machine_passwd = generate_and_set_passwd( $krb5ccname, $realm, $dryrun,
                                           $passlen, $minnum, $minlower, $minupper, $minspecial );

print "Finding Key Version Number.\n";
if (!$dryrun) {
    $kvno = deduce_kvno( $domain_controller, $baseDN, $upcase_nodename, $krb5ccname );
    print "KVNO: $kvno\n";
}
else {
    print "Dryrun: KVNO is probably '$kvno'\n";
}


finalize_machine_account( $upcase_nodename, $baseDN, $krb5ccname,
                          $userAccountControlBASE, $domain_controller, $dryrun );

@enc_types = deduce_and_set_enc_types( $upcase_nodename, $baseDN, $krb5ccname, $domain_controller, $dryrun );

kt_write( $machine_passwd, $fqdn, $realm, $kvno, $keytab_file, \@enc_types );

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

if ($^O eq 'solaris') {
    correct_idmap( $dryrun, $leave );
}

print "The machine is now joined to the domain, rejoice!\n";

exit 0;

__END__

=head1 NAME

plaidjoin - Join or Disjoin a computer from the domain.

=head1 SYNOPSIS

Usage: plaidjoin  [options] [domain [nodename]]
Usage: plaidleave [options] [domain [nodename]]

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
