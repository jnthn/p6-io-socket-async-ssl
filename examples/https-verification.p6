use IO::Socket::Async::SSL;

# This demonstrates certification verification. Change the value of
# $insecure to True to get it to connect even though the cert is bad.
my $insecure = False;

my $conn = await IO::Socket::Async::SSL.connect('wrong.host.badssl.com', 443, :$insecure);
$conn.print: "GET / HTTP/1.0\r\n\r\n";
react {
    whenever $conn {
        .print
    }
}
$conn.close;
