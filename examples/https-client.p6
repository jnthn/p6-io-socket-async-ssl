use IO::Socket::Async::SSL;

# This connects to the https-server.p6 example, and demonstrates using
# a custom CA in order to verify it.

my $ca-file = 'examples/ca-crt.pem';
my $conn = await IO::Socket::Async::SSL.connect('localhost', 4433, :$ca-file);
$conn.print: "GET / HTTP/1.0\r\n\r\n";
react {
    whenever $conn {
        .print
    }
}
$conn.close;
