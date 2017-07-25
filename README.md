# IO::Socket::Async::SSL [![Build Status](https://travis-ci.org/jnthn/p6-io-socket-async-ssl.svg?branch=master)](https://travis-ci.org/jnthn/p6-io-socket-async-ssl)

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

## Client

The `connect` method on `IO::Socket::Async::SSL` is used to establish a SSL
connection to a server. It requies two positional arguments, which specify the
`host` and `port` to connect to. It returns a `Promise`, which will be kept
with an `IO::Socket::Async::SSL` instance when the connection is established
and the SSL handshake completed.

    my $conn = await IO::Socket::Async::SSL.connect($host, $port);

By default, the SSL certificate will be verified, using the default set of
accepted Certificate Authorities. The `Promise` return by `conenct` will be
broken if verification fails.

Sometimes it is convenient to create a CA and use it to sign certificates for
internal use, for example to secure communications between a set of services
on an internal network. In this case, the `ca-file` named argument can be
passed to specify the certificate authority certificate file:

    my $ca-file = '/config/ca-crt.pem';
    my $conn = await IO::Socket::Async::SSL.connect('user-service', 443, :$ca-file);

Alternatively, a `ca-path` argument can be specified, indicating a directory
where one or more certificates may be found.

It is possible to disable certificate verification by passing the `insecure`
named argument a true value. As the name suggests, **this is not a secure
configuration**, since there is no way for the client to be sure that it is
communicating with the intended server. Therefore, it is vulnerable to
man-in-the-middle attacks.

## Server

The `listen` method returns a `Supply` that, when tapped, will start an SSL
server. The server can be shut down by closing the tap. Whenever a connection
is made to the server, the `Supply` will emit an `IO::Socket::Async::SSL`
instance. The `listen` method requires two positional arguments, specifying
the `host` and `port` to listen on. Two named arguments are also required,
providing the `certificate-file` and `private-key-file`.

    my %ssl-config =
        certificate-file => 'server-crt.pem',
        private-key-file => 'server-key.pem';
    my $connections = IO::Socket::Async::SSL.listen('localhost', 4433, |%ssl-config);
    react {
        my $listener = do whenever $connections -> $conn {
            say "Got a connection!";
            $conn.close;
        }

        whenever signal(SIGINT) {
            say "Shutting down...";
            $listener.close;
            exit;
        }
    }

## Common client and server functionality

Both the `connect` and `listen` methods take the following optional named
arguments:

* `enc`, which specifies the encoding to use when the socket is used in
  character mode. Defaults to `utf-8`.
* `scheduler`, which specifies the scheduler to use for processing events from
  the underlying `IO::Socket::Async` instance. The default is `$*SCHEDULER`.
  There is rarely a need to change this.

The `Supply`, `print`, `write`, and `close` methods have the same semantics as
in [IO::Socket::Async](https://docs.perl6.org/type/IO$COLON$COLONSocket$COLON$COLONAsync).

## Bugs, feature requests, and contributions

Please use GitHub Issues to file bug reports and feature requests. If you wish
to contribute to this module, please file a GitHub Pull Request, or email a
Git patch (produced using `format-patch`) to [jnthn@jnthn.net](mailto:jnthn@jnthn.net).
