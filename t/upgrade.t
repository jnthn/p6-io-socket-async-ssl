use Test;
use IO::Socket::Async::SSL;

my constant TEST_PORT = 54328;

my $ready = Promise.new;
start {
    react {
        whenever IO::Socket::Async.listen('localhost', TEST_PORT) -> $plain-conn {
            whenever $plain-conn.Supply -> $start {
                if $start eq "Psst, let's talk securely!\n" {
                    my $enc-conn-handshake = IO::Socket::Async::SSL.upgrade-server(
                        $plain-conn,
                        private-key-file => 't/certs-and-keys/server.key',
                        certificate-file => 't/certs-and-keys/server-bundle.crt'
                    );
                    whenever $enc-conn-handshake -> $enc-conn {
                        uc-service($enc-conn);
                    }
                    $plain-conn.print("OK, let's talk securely!\n");
                    last;
                }
                else {
                    $plain-conn.print("OK, let's talk insecurely\n");
                    uc-service($plain-conn);
                }
            }
        }

        sub uc-service($conn) {
            whenever $conn -> $crypt-text {
                whenever $conn.print($crypt-text.uc) {
                    $conn.close;
                }
            }
        }

        $ready.keep;
    }
    CATCH {
        diag $_;
        exit 1;
    }
}
await $ready;

my $plain-conn = await IO::Socket::Async.connect('localhost', TEST_PORT);
await $plain-conn.print("Psst, let's talk securely!\n");
react whenever $plain-conn -> $msg {
    is $msg, "OK, let's talk securely!\n", 'Got expected upgrade response';

    my $enc-conn-handshake = IO::Socket::Async::SSL.upgrade-client(
        $plain-conn,
        host => 'localhost',
        ca-file => 't/certs-and-keys/ca.crt');
    whenever $enc-conn-handshake -> $enc-conn {
        isa-ok $enc-conn, IO::Socket::Async::SSL, 'Got upgraded connection on client side';
        await $enc-conn.print("hello!\n");
        whenever $enc-conn.head -> $got {
            is $got, "HELLO!\n", 'Got correct message from upgraded connection';
            done;
        }
    }

    last;
}

done-testing;
