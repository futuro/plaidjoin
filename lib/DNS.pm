package DNS;

use Net::DNS;

use subs qw(
    dns_search check_dnssrv netmask_to_length num_to_dot_quad
    dot_quad_to_num enumerate_subnets dn_to_dns dns_to_dn get_SRVs canonical_resolve
    deduce_domain get_base_dn enumerate_KPWs enumerate_GCs enumerate_KDCs enumerate_DCs );

# Do a DNS search for the 'record' associated with 'name'
# TODO: Think about better incorporating the verbose variable (is it only for warnings,
#       or should it be for everything).
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

# Convert an AD-style domain DN to a DNS domainname
# This will convert regardless of case.
# Input:
#   Str: The DN to convert
# Output:
#   Str: The converted DN
#   OR
#   '' : There was no DN to convert
sub dn_to_dns {
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
sub dns_to_dn {
    my $dnsDN = '';

    my $domainname = shift;

    if ($domainname) {
        $domainname =~ s/\./,DC=/g;
        $dnsDN = "DC=" . $domainname;
    }

    return $dnsDN;
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

# Find the canonical name for a domainname
# Input:
#   Str: The domain name to search for
# Ouput:
#   Str: The canonical FQDN for the domain
#   OR
#   '' : The empty string (if the input doesn't resolve to anything)
sub canonical_resolve {
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
sub deduce_domain {
    my $query = Net::DNS::Resolver->new;
    my $response = $query->search('_ldap._tcp.dc._msdcs', 'SRV');

    my $domain = '';

    # Copy $response->string into $domain, then do a search/replace on $domain
    ($domain = $response->string) =~ s/.*_ldap._tcp.dc._msdcs.([\w.]+)\.\s.*/$1/s;
    return $domain;
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
    my $domainname = (shift or '');
    my $container  = (shift or '');

    my $baseDN = '';

    my $dnsDN = '';

    $container = ($container . ",") unless !$container;

    $dnsDN  = dns_to_dn($domainname);
    $baseDN = $container . $dnsDN;

    return $baseDN;
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

1;
# vim: ts=4 sw=4 et fdm=syntax
