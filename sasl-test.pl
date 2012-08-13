#!/usr/bin/perl

use strict;
use warnings;

use Authen::Krb5;
use Authen::SASL;
use Net::LDAP;
use IO::Socket;

my $SERVICE = "krbtgt";
my $SERVER = "neo.cose.umn.edu";

Authen::Krb5::init_context();

my $sasl = Authen::SASL->new(
            mechanism => 'GSSAPI',
            callback => {
                user => \&getuser,
                pass => \&getpass,
                auth => \&getauth,
            });

my $host = $ARGV[0] || die "\nusage: $0 <ldapserver> \n\n";
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
