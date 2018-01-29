use Test;
use IO::Socket::Async::SSL;

my constant TEST_PORT = 54334;

my $server = IO::Socket::Async::SSL.listen(
    'localhost', TEST_PORT,
    private-key-file => 't/certs-and-keys/server-key.pem',
    certificate-file => 't/certs-and-keys/server-crt.pem',
    ciphers => 'HIGH'
);
my $echo-server-tap = $server.tap: -> $conn {
    $conn.Supply(:bin).tap: -> $data {
        $conn.write($data);
    }
}
END $echo-server-tap.close;

dies-ok 
    {
        await IO::Socket::Async::SSL.connect('localhost', TEST_PORT,
            ca-file => 't/certs-and-keys/ca-crt.pem',
            ciphers => 'MEDIUM')
    },
    'Connection fails when the are non-matching cipher expectations';

lives-ok 
    {
        my $s = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT,
            ca-file => 't/certs-and-keys/ca-crt.pem',
            ciphers => 'HIGH');
        $s.close;
    },
    'Connection ok when ciphers match up';

done-testing;
