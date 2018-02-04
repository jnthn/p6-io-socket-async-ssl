use Test;
use IO::Socket::Async::SSL;

my constant TEST_PORT = 54334;

my $server = IO::Socket::Async::SSL.listen(
    'localhost', TEST_PORT,
    private-key-file => 't/certs-and-keys/server.key',
    certificate-file => 't/certs-and-keys/server-bundle.crt',
    ciphers => 'ECDHE-RSA-AES256-GCM-SHA384'
);
my $echo-server-tap = $server.tap: -> $conn {
    $conn.Supply(:bin).tap: -> $data {
        $conn.write($data);
    }
}
END $echo-server-tap.close;

lives-ok
    {
        my $s = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT,
            ca-file => 't/certs-and-keys/ca.crt',
            ciphers => 'ECDHE-RSA-AES256-GCM-SHA384');
        $s.close;
    },
    'Connection with cipher doing key exchange works';

done-testing;
