use IO::Socket::Async::SSL;
use Test;

my $conn;
lives-ok { $conn = await IO::Socket::Async::SSL.connect("httpbin.org", 443) },
    'Can connect to a site that needs Server Name Identification';
$conn.?close;

done-testing;
