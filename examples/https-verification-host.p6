use IO::Socket::Async::SSL;

# This demonstrates verification of the host name on the certificate.
# Set $insecure to True to get it to connect OK.
my $insecure = False;

my $conn = await IO::Socket::Async::SSL.connect('wrong.host.badssl.com', 443, :$insecure);
$conn.print: "GET / HTTP/1.0\r\nHost: wrong.host.badssl.com\r\n\r\n";
react {
    whenever $conn {
        .print
    }
}
$conn.close;
