package Files;

use strict;
use warnings;

use File::Temp qw(tempfile);

use subs qw(
    generate_tmpfile );

BEGIN {
    require Exporter;

    # Inherit from Exporter to export functions and variables
    our @ISA = qw(Exporter);

    # Functions and variables which are exported by default
    our @EXPORT = qw( generate_tmpfile );
}

# Generate a temp file name (e.g. "/tmp/foo.bar.1241"). Don't open it.
# Defaults:
#   Str: the template has a defualt
#   Str: The directory the tempfile is made in has a default
# Input:
#   Str: The template to use
# Ouput:
#   Str: The path to the temp file
sub generate_tmpfile {
    my $template = (shift or 'default-plaidjoin-tmpfile.XXXXXX');
    my $dir      = (shift or '/tmp');

    my $filename = '';

    (undef, $filename) = tempfile($template, DIR => $dir, OPEN => 0);

    return $filename;
}

1;
# vim: ts=4 sw=4 et fdm=syntax
