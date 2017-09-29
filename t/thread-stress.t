use Test;
use IO::Socket::Async::SSL;

my constant TEST_PORT = 54330;

my $ready = Promise.new;
start react {
    my %conf = 
        private-key-file => 't/certs-and-keys/server-key.pem',
        certificate-file => 't/certs-and-keys/server-crt.pem';
    whenever IO::Socket::Async::SSL.listen('localhost', TEST_PORT, |%conf) -> $conn {
        whenever $conn.Supply(:bin) -> $data {
            whenever $conn.write($data) {}
        }
    }
    $ready.keep(True);
}
await $ready;

await do for ^4 {
    start {
        for 1..50 -> $i {
            my $ca-file = 't/certs-and-keys/ca-crt.pem';
            my $conn = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, :$ca-file);
            my $expected = "[string $i]" x (8 * $i);
            await $conn.write($expected.encode('ascii'));
            my $got = '';
            react {
                whenever $conn.Supply(:bin) {
                    $got ~= .decode('ascii');
                    if $got.chars eq $expected.chars {
                        $conn.close;
                        done;
                    }
                }
                whenever Promise.in(5) {
                    $conn.close;
                    done;
                }
            }
            die "Oops ($got ne $expected)" unless $got eq $expected;
        }
    } 
}

pass 'Thread stress-test lived';

done-testing;
