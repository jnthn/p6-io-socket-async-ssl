use Test;
use IO::Socket::Async::SSL;

my constant TEST_PORT = 54333;

my $server = IO::Socket::Async::SSL.listen(
    'localhost', TEST_PORT,
    private-key-file => 't/certs-and-keys/server.key',
    certificate-file => 't/certs-and-keys/server-bundle.crt'
);

my ($conns, $quits) = 0, 0;
my $server-tap = $server.tap:
    -> $conn { $conns++ },
    quit => { $quits++ };

my $no-hang = start react {
    my $raw-conn = await IO::Socket::Async.connect('localhost', TEST_PORT);
    whenever $raw-conn {
    }
    whenever $raw-conn.print("GET / HTTP/1.0\r\n\r\n") { }
}

await Promise.anyof($no-hang, Promise.in(10));
ok $no-hang, 'Sending non-SSL to SSL socket does not hang (connection closed)';

$server-tap.close;
is $conns, 0, 'No connection emitted';
is $quits, 0, 'Server tap did not QUIT on bad incoming connection';

done-testing;
