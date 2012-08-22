package LDAP;

use strict;
use warnings;

use Net::LDAP;
use Authen::SASL;

use subs qw(
    gen_ldap_bind ldapsearch ldapdelete ldapreplace ldapadd );

BEGIN {
    require Exporter;

    # Inherit from Exporter to export functions and variables
    our @ISA = qw(Exporter);

    # Functions and variables which are exported by default
    our @EXPORT =qw(
        gen_ldap_bind ldapsearch ldapdelete ldapreplace ldapadd );
}

# This will create an LDAP bind object
# XXX: This requires that you have already authenticated using whatever SASL
#      mechanism you prefer
# Input:
#   Str: The host to connect to (Default: N/A)
#   Str: The SASL mechanism you want (Default: GSSAPI)
sub gen_ldap_bind {
    my $host      = (shift or '');
    my $mechanism = (shift or 'GSSAPI');

    my $sasl;
    my $ldap;
    my $dse;

    # We can't bind if we don't have a host, so return 'undef';
    return $ldap unless $host;

    $sasl = Authen::SASL->new( mechanism => $mechanism, );
    $ldap = Net::LDAP->new(
            $host,
            onerror => 'warn' ,
        ) or die "Cannot connect to LDAP host '$host': ";
        # NOTE: Is this second die call redundant if 'onerror' is set to 'die'?

    # Make sure that '$mechanism' is supported by the server
    $dse = $ldap->root_dse();
    $dse->supported_sasl_mechanism( $mechanism )
        or die "\n sorry, $host does not support $mechanism...\n";

    $ldap->bind( sasl => $sasl ) or die $@, $sasl->error(), "\n Terminating.\n";

    return $ldap;
}

sub ldapsearch {
    my $ldap   = (shift or '');
    my $baseDN = (shift or '');
    my $scope  = (shift or 'sub');
    my $filter = (shift or '(objectClass=*)');
    my @attrs  = (shift or []);

    my $result;

    # We can't search without an ldap object, so return the default message (undef, probably)
    return $result unless $ldap;

    $result = $ldap->search(
                base   => $baseDN,
                scope  => $scope,
                filter => $filter,
                attrs  => @attrs,
            );

    return $result;
}

sub ldapdelete {
    my $ldap = (shift or '');
    my $dn   = (shift or '');

    my $result;

    # We can't do anything without an ldap object, so return the default message (undef, probably)
    return $result unless $ldap;

    $result = $ldap->delete( $dn );

    return $result;
}

# Input:
#   Scalar  : The ldap object to query with
#   Scalar  : The Distinguished Name to use
#   HashRef : A reference to the hash containing the desired attributes to replace
sub ldapreplace {
    my $ldap     = (shift or '');
    my $dn       = (shift or '');
    my $attr_ref = (shift or +{});

    my $result;

    return $result unless ($ldap and $dn and $attr_ref);

    $result = $ldap->modify( $dn, replace => %{$attr_ref} );

    return $result;
}

# Input:
#   Scalar  : The ldap object to query with
#   Scalar  : The Distinguished Name to use
#   HashRef : A reference to the array with the desired attributes to add
sub ldapadd {
    my $ldap     = (shift or '');
    my $dn       = (shift or '');
    my $attr_ref = (shift or +{});

    my $result;

    return $result unless ($ldap and $dn and $attr_ref);

    $result = $ldap->add( $dn, attrs => [ %{$attr_ref} ] );

    return $result;
}

1;
# vim: ts=4 sw=4 et fdm=syntax
