use IO::Socket::Async::SSL;
use Test;

my $conn;
lives-ok { $conn = await IO::Socket::Async::SSL.connect("www.youtube.com", 443) },
    'Can connect to a site using a wildcard certificate';
$conn.?close;

done-testing;
