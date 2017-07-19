use Test;
use IO::Socket::Async::SSL;

my constant TEST_PORT = 54329;

my $server = IO::Socket::Async::SSL.listen(
    'localhost', TEST_PORT,
    private-key-file => 't/certs-and-keys/server-key.pem',
    certificate-file => 't/certs-and-keys/server-crt.pem'
);
isa-ok $server, Supply, 'listen method returns a Supply';
dies-ok { await IO::Socket::Async.connect('localhost', TEST_PORT) },
    'Server not listening until Supply is tapped';

{
    my $echo-server-tap = $server.tap: -> $conn {
        $conn.Supply(:bin).tap: -> $data {
            $conn.write($data);
        }
    }
    my $raw-conn;
    lives-ok { $raw-conn = await IO::Socket::Async.connect('localhost', TEST_PORT) },
        'Server listens after Supply is tapped';
    $raw-conn.close;

    my $ssl-conn;
    lives-ok { $ssl-conn = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT,
            ca-file => 't/certs-and-keys/ca-crt.pem') },
        'Can establish and SSL connection to the SSL server';

    lives-ok { $ssl-conn.write('penguin'.encode('ascii')) },
        'Can write to the SSL server';

    my $incoming = $ssl-conn.Supply(:bin);
    isa-ok $incoming, Supply, 'Can get a Supply of incoming data';
    my $got = '';
    await Promise.anyof: Promise.in(5), start react {
        whenever $incoming {
            $got ~= .decode('ascii');
            done if $got eq 'penguin';
        }
    }
    is $got, 'penguin', 'SSL echo server got back expected data';

    lives-ok { $ssl-conn.close }, 'Can close the SSL server connection';

    throws-like { await IO::Socket::Async::SSL.connect('localhost', TEST_PORT) },
        X::IO::Socket::Async::SSL::Verification,
        'Without specifying a CA, our self-signed server fails verification';
    throws-like { await IO::Socket::Async::SSL.connect('127.0.0.1', TEST_PORT,
            ca-file => 't/certs-and-keys/ca-crt.pem') },
        X::IO::Socket::Async::SSL::Verification,
        'When we connect to 127.0.0.1, certificate for localhost will not do';

    $echo-server-tap.close;
    dies-ok { await IO::Socket::Async.connect('localhost', TEST_PORT) },
        'Server not listening after tap is closed';
}

{
    my $server = IO::Socket::Async::SSL.listen(
        'localhost', TEST_PORT+1,
        private-key-file => 't/certs-and-keys/server-key.pem',
        certificate-file => 't/certs-and-keys/server-crt.pem',
        alpn => <h2 http/1.1>
    );

    my $echo-server-tap = $server.tap: -> $conn {
        $conn.supply(:bin).tap: -> $data { $conn.write($data); }
    };

    my $conn = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT+1,
                                                    ca-file => 't/certs-and-keys/ca-crt.pem',
                                                    alpn => <h2 http/1.1>);
    is $conn.alpn-result, 'h2', 'Simple server-side ALPN works';
    $conn.?close;
    $echo-server-tap.close;
}

{
    my $server = IO::Socket::Async::SSL.listen(
        'localhost', TEST_PORT+1,
        private-key-file => 't/certs-and-keys/server-key.pem',
        certificate-file => 't/certs-and-keys/server-crt.pem',
        alpn => sub (@options) {
            ok @options.join(', ') eq 'h2, http/1.1', 'Passed protocols are correct';
            any(@options) eq 'h2' ?? 'h2' !! Nil;
        }
    );

    my $echo-server-tap = $server.tap: -> $conn {
        $conn.supply(:bin).tap: -> $data {
            $conn.write($data);
        }
    };

    my $conn = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT+1,
                                                    ca-file => 't/certs-and-keys/ca-crt.pem',
                                                    alpn => <h2 http/1.1>);
    is $conn.alpn-result, 'h2', 'Server-side ALPN with a subroutine works';
    $conn.?close;
    $echo-server-tap.close;
}

{
    my $server = IO::Socket::Async::SSL.listen(
        'localhost', TEST_PORT+1,
        private-key-file => 't/certs-and-keys/server-key.pem',
        certificate-file => 't/certs-and-keys/server-crt.pem',
        alpn => <h2 http/1.1>
    );

    my $echo-server-tap = $server.tap: -> $conn {
        $conn.supply(:bin).tap: -> $data {
            $conn.write($data);
        }
    };

    my $p1 = Promise.new;
    my $p2 = Promise.new;
    start {
        my $conn1 = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT+1,
                                                         ca-file => 't/certs-and-keys/ca-crt.pem',
                                                         alpn => <h2 http/1.1>);
        $conn1.?close;
        $p1.keep;
    }
    start {
        my $conn2 = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT+1,
                                                         ca-file => 't/certs-and-keys/ca-crt.pem',
                                                         alpn => <h2 http/1.1>);
        $conn2.?close;
        $p2.keep;
    }
    await Promise.anyof(Promise.in(5), Promise.allof($p1, $p2));
    ok $p1.status ~~ Kept, 'Multiply clients with ALPN work';
    $echo-server-tap.close;
}

done-testing;
