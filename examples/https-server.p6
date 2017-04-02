use IO::Socket::Async::SSL;

react {
    my %ssl-config =
        certificate-file => 'examples/server-crt.pem',
        private-key-file => 'examples/server-key.pem';
    whenever IO::Socket::Async::SSL.listen('localhost', 4433, |%ssl-config) -> $conn {
        my $req = '';
        whenever $conn {
            $req ~= $_;
            if $req.contains("\r\n\r\n") {
                say $req.lines[0];
                await $conn.print(
                    "HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n" ~
                    "<strong>Hello from a Perl 6 HTTP server</strong>\n");
                $conn.close;
            }
        }
    }
}
