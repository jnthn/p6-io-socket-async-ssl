use IO::Socket::Async::SSL;

my $conn = await IO::Socket::Async::SSL.connect('www.perl6.org', 443);
say "connected";
$conn.print: "GET / HTTP/1.0\r\n\r\n";
react {
    whenever $conn {
        .print
    }
}
$conn.close;
