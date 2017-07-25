use IO::Socket::Async::SSL;
use Test;

my $conn;
lives-ok { $conn = await IO::Socket::Async::SSL.connect('google.co.uk', 443,
                                                        alpn => <h2 http/1.1>);
           ok $conn.alpn-result eq 'h2', 'ALPN for the client works' },
    'ALPN can be used';
$conn.?close;

done-testing;
