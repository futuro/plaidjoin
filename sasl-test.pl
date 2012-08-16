#!/usr/bin/perl

use strict;
use warnings;

use Authen::Krb5;
use Authen::SASL;
use Net::LDAP;
use IO::Socket;
use Term::ReadLine;
use Term::ReadKey;
use GSSAPI;

my $host = $ARGV[0] || die "\nusage: $0 <ldapserver> <user>\n\n";
my $user = $ARGV[1] || die "\nusage: $0 <ldapserver> <user>\n\n";

my $SERVICE = "krbtgt";

my $krb5con = Authen::Krb5::init_context();
my $princ = Authen::Krb5::parse_name($user);

print "Getting creds for '".$princ->data."@".$princ->realm."'\n";
print "Please enter your password: ";
ReadMode('noecho');
my $pass = ReadLine(0);
chomp $pass;
ReadMode('restore');
print "\n";

my $creds = Authen::Krb5::get_init_creds_password($princ, $pass);
undef $pass; # Clear the variable so we're not storing sensitive plaintext data in memory
my $ccache = Authen::Krb5::cc_resolve("FILE:/tmp/plaidjoin_sasltest");
#my $ccache = Authen::Krb5::cc_default();
Authen::Krb5::Ccache::initialize($ccache, $princ);
$ccache->store_cred($creds);

## XXX: This is currently the only way I know of to pass a non-default ticket location
##      to SASL. In Authen::SASL::Perl::GSSAPI(3m), it speaks of passing in a GSSAPI::Cred object
##      via the Authen::SASL callback hash using the 'pass' key. Diggin into the GSSAPI perl module,
##      and the GSSAPI documentation as well, I haven't found a good way to use a different location
##      for the keytab aside from setting KRB5CCNAME. There is no way to initialize a new GSSAPI::Cred
##      object to pass in anywhere. I am simply at a loss as to how to do this any other way
##
##      On the plus(negative?) side, setting this once will affect the whole program, and can be picked
##      up by child processes.
$ENV{KRB5CCNAME}="/tmp/plaidjoin_sasltest";
print "\$KRB5CCNAME is \"$ENV{KRB5CCNAME}\"\n";
my $sasl = Authen::SASL->new( mechanism => 'GSSAPI', );

my $ldap = Net::LDAP->new(
        $host,
        onerror => 'die' ,
    ) or die "Cannot connect to LDAP host '$host': ";

my $dse = $ldap->root_dse();

$dse->supported_sasl_mechanism( 'GSSAPI' ) || die "\n sorry, $host does not support GSSAPI...\n";

$ldap->bind( sasl => $sasl ) or die $@, $sasl->error(), "\n Terminating.\n";

print "SASL bind to $host successful.\n";

sub getpass {
    my $passwd;
}

# vim: ts=4 sw=4 et fdm=syntax
