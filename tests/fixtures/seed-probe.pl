# Functional probe for an explicitly admitted seed; never a host Perl fallback.
BEGIN {
    die "missing declared Perl paths\n" unless defined $ENV{PERL5LIB};
    @INC = split /:/, $ENV{PERL5LIB}, -1;
    die "invalid declared Perl paths\n" unless @INC == 2;
    for (@INC) { die "invalid declared Perl path\n" unless m{^/syrox/store/[^/]+/tools/usr/(?:lib/perl5/5\.42/core_perl|share/perl5/core_perl)$}; }
}
use strict;
use warnings;
use Carp ();
use JSON::PP ();
use FindBin ();
use bigint;
use List::Util qw(max);
use Cwd qw(abs_path);
use File::Basename ();
use File::stat ();
use POSIX ();
use Getopt::Long ();
use DB_File ();
use Fcntl qw(O_RDWR O_CREAT);
my $root = shift @ARGV;
die "missing tools root\n" unless defined $root && @ARGV == 0;
$root = abs_path($root);
die "incorrect declared Perl paths\n" unless join(':', @INC) eq "$root/usr/lib/perl5/5.42/core_perl:$root/usr/share/perl5/core_perl";
die "JSON operation\n" unless JSON::PP::decode_json(JSON::PP::encode_json({probe => [1,2,3]}))->{probe}[2] == 3;
die "XS List::Util operation\n" unless max(1,9,3) == 9;
die "XS POSIX operation\n" unless POSIX::floor(3.75) == 3;
die "Cwd/FindBin operation\n" unless abs_path($FindBin::Bin) eq abs_path('.');
die "Carp operation\n" unless Carp::shortmess('seed-probe') =~ /seed-probe/;
my %database;
tie %database, 'DB_File', 'probe.db', O_RDWR | O_CREAT, 0600, $DB_File::DB_HASH or die "DB_File open\n";
$database{probe} = 'roundtrip';
die "DB_File operation\n" unless $database{probe} eq 'roundtrip';
untie %database;
unlink 'probe.db' or die "DB_File cleanup\n";
for my $file (values %INC) {
    my $path = abs_path($file);
    die "module outside declared tools\n" unless defined $path && index($path, "$root/") == 0;
}
for my $file (@DynaLoader::dl_shared_objects) {
    my $path = abs_path($file);
    die "XS outside declared tools\n" unless defined $path && index($path, "$root/") == 0;
}
for my $suffix ('/auto/List/Util/Util.so', '/auto/Cwd/Cwd.so', '/auto/POSIX/POSIX.so', '/auto/DB_File/DB_File.so') {
    die "required XS not loaded\n" unless grep { /\Q$suffix\E\z/ } @DynaLoader::dl_shared_objects;
}
