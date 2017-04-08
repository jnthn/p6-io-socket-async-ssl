# IO::Socket::Async::SSL

This module provides a secure sockets implementation with an API very much
like that of the Perl 6 built-in `IO::Socket::Async` class. For the client
case, provided the standard certificate and host verification are sufficient,
it is drop-in replacement. The server case only needs two extra arguments to
`listen`, specifying the server key and certificate.

As with `IO::Socket::Async`, it is safe to have concurrent connections and to
share them across threads.

## Synopsis

Client:

    use IO::Socket::Async::SSL;

    my $conn = await IO::Socket::Async::SSL.connect('www.perl6.org', 443);
    $conn.print: "GET / HTTP/1.0\r\nHost: www.perl6.org\r\n\r\n";
    react {
        whenever $conn {
            .print
        }
    }
    $conn.close;

Server (assumes certificate and key files `server-crt.pem` and `server-key.pem`):

    use IO::Socket::Async::SSL;

    react {
        my %ssl-config =
            certificate-file => 'server-crt.pem',
            private-key-file => 'server-key.pem';
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
