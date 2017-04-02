use OpenSSL;
use OpenSSL::Bio;
use OpenSSL::Ctx;
use OpenSSL::EVP;
use OpenSSL::SSL;

# XXX Contribute these back to the OpenSSL binding.
use OpenSSL::NativeLib;
use NativeCall;
sub BIO_new(OpenSSL::Bio::BIO_METHOD) returns OpaquePointer is native(&gen-lib) {*}
sub BIO_s_mem() returns OpenSSL::Bio::BIO_METHOD is native(&gen-lib) {*}
sub SSL_do_handshake(OpenSSL::SSL::SSL) returns int32 is native(&gen-lib) {*}

# Per OpenSSL module, make a simple call to ensure libeay32.dll is loaded before
# ssleay32.dll on Windows.
OpenSSL::EVP::EVP_aes_128_cbc();

# On first load of the module, initialize the library.
OpenSSL::SSL::SSL_load_error_strings();
OpenSSL::SSL::SSL_library_init();

# For now, we'll put a lock around all of our interactions with the library.
# There are smarter things possible.
my $lib-lock = Lock.new;

class IO::Socket::Async::SSL {
    has IO::Socket::Async $!sock;
    has OpenSSL::Ctx::SSL_CTX $!ctx;
    has OpenSSL::SSL::SSL $!ssl;
    has $!read-bio;
    has $!write-bio;
    has $!connected-promise;
    has $!accepted-promise;
    has $!shutdown-promise;
    has $.enc;
    has Supplier::Preserving $!bytes-received .= new;

    method new() {
        die "Cannot create an asynchronous SSL socket directly; please use\n" ~
            "IO::Socket::Async::SSL.connect or IO::Socket::Async::SSL.listen\n";
    }

    submethod BUILD(:$!sock, :$!enc, :$!ctx, :$!ssl, :$!read-bio, :$!write-bio,
                    :$!connected-promise, :$!accepted-promise) {
        $!sock.Supply(:bin).tap:
            -> Blob $data {
                $lib-lock.protect: {
                    OpenSSL::Bio::BIO_write($!read-bio, $data, $data.bytes);
                    self!handle-buffers();
                }
            },
            done => {
                $lib-lock.protect: {
                    self!handle-buffers();
                }
                $!bytes-received.done;
            },
            quit => {
                $!bytes-received.quit($_);
            };
        self!handle-buffers();
    }

    method connect(IO::Socket::Async::SSL:U: Str() $host, Int() $port,
                   :$enc = 'utf8', :$scheduler = $*SCHEDULER,
                   OpenSSL::ProtocolVersion :$version = -1) {
        start {
            my $sock = await IO::Socket::Async.connect($host, $port, :$scheduler);
            my $connected-promise = Promise.new;
            $lib-lock.protect: {
                my $ctx = self!build-client-ctx($version);
                my $ssl = OpenSSL::SSL::SSL_new($ctx);
                my $read-bio = BIO_new(BIO_s_mem());
                my $write-bio = BIO_new(BIO_s_mem());
                OpenSSL::SSL::SSL_set_bio($ssl, $read-bio, $write-bio);
                OpenSSL::SSL::SSL_set_connect_state($ssl);
                SSL_do_handshake($ssl);
                self.bless(
                    :$sock, :$enc, :$ctx, :$ssl, :$read-bio, :$write-bio,
                    :$connected-promise
                )
            }
            await $connected-promise;
        }
    }

    method !build-client-ctx($version) {
        my $method = do given $version {
            when 2 { OpenSSL::Method::SSLv2_client_method() }
            when 3 { OpenSSL::Method::SSLv3_client_method() }
            when 1 { OpenSSL::Method::TLSv1_client_method() }
            when 1.1 { OpenSSL::Method::TLSv1_1_client_method() }
            when 1.2 { OpenSSL::Method::TLSv1_2_client_method() }
            default {
                try { OpenSSL::Method::TLSv1_2_client_method() } ||
                    try { OpenSSL::Method::TLSv1_client_method() }
            }
        }
        OpenSSL::Ctx::SSL_CTX_new($method)
    }

    method listen(IO::Socket::Async::SSL:U: Str() $host, Int() $port,
                  :$enc = 'utf8', :$scheduler = $*SCHEDULER,
                  OpenSSL::ProtocolVersion :$version = -1,
                  :$certificate-file, :$private-key-file) {
        supply {
            whenever IO::Socket::Async.listen($host, $port, :$scheduler) -> $sock {
                my $accepted-promise = Promise.new;
                $lib-lock.protect: {
                    my $ctx = self!build-server-ctx($version);
                    with $certificate-file {
                        OpenSSL::Ctx::SSL_CTX_use_certificate_file($ctx,
                            $certificate-file, 1);
                    }
                    with $private-key-file {
                        OpenSSL::Ctx::SSL_CTX_use_PrivateKey_file($ctx,
                            $private-key-file, 1);
                    }
                    my $ssl = OpenSSL::SSL::SSL_new($ctx);
                    my $read-bio = BIO_new(BIO_s_mem());
                    my $write-bio = BIO_new(BIO_s_mem());
                    OpenSSL::SSL::SSL_set_bio($ssl, $read-bio, $write-bio);
                    OpenSSL::SSL::SSL_set_accept_state($ssl);
                    self.bless(
                        :$sock, :$enc, :$ctx, :$ssl, :$read-bio, :$write-bio,
                        :$accepted-promise
                    )
                }
                whenever $accepted-promise -> $ssl-socket {
                    emit $ssl-socket;
                }
            }
        }
    }

    method !build-server-ctx($version) {
        my $method = do given $version {
            when 2 { OpenSSL::Method::SSLv2_server_method() }
            when 3 { OpenSSL::Method::SSLv3_server_method() }
            when 1 { OpenSSL::Method::TLSv1_server_method() }
            when 1.1 { OpenSSL::Method::TLSv1_1_server_method() }
            when 1.2 { OpenSSL::Method::TLSv1_2_server_method() }
            default {
                try { OpenSSL::Method::TLSv1_2_server_method() } ||
                    try { OpenSSL::Method::TLSv1_server_method() }
            }
        }
        OpenSSL::Ctx::SSL_CTX_new($method)
    }

    method !handle-buffers() {
        if $!connected-promise || $!accepted-promise {
            my $buf = Buf.allocate(32768);
            my $bytes-read = OpenSSL::SSL::SSL_read($!ssl, $buf, 32768);
            if $bytes-read >= 0 {
                $!bytes-received.emit($buf.subbuf(0, $bytes-read));
            }
            else {
                # XXX error handling...
            }
            with $!shutdown-promise {
                my $rc = OpenSSL::SSL::SSL_shutdown($!ssl);
                self!flush-read-bio();
                if $rc >= 0 {
                    $!shutdown-promise.keep(True);
                }
                else {
                    # XXX Error handling
                }
            }
        }
        orwith $!connected-promise {
            my $rc = OpenSSL::SSL::SSL_connect($!ssl);
            if $rc < 0 {
                # XXX Error check needed
            }
            else {
                $!connected-promise.keep(self);
            }
            self!flush-read-bio();
        }
        orwith $!accepted-promise {
            my $rc = OpenSSL::SSL::SSL_accept($!ssl);
            if $rc < 0 {
                # XXX Error check needed
            }
            else {
                $!accepted-promise.keep(self);
            }
            self!flush-read-bio();
        }
    }

    method !flush-read-bio() {
        my $buf = Buf.allocate(32768);
        while OpenSSL::Bio::BIO_read($!write-bio, $buf, 32768) -> $bytes-read {
            last if $bytes-read < 0;
            $!sock.write($buf.subbuf(0, $bytes-read));
        }
    }

    method Supply(:$bin, :$scheduler = $*SCHEDULER) {
        if $bin {
            $!bytes-received.Supply.schedule-on($scheduler)
        }
        else {
            supply {
                whenever $!bytes-received.Supply.schedule-on($scheduler) {
                    # XXX use streaming decoder and correct encoding
                    emit .decode('latin-1')
                }
            }
        }
    }

    method print(IO::Socket::Async::SSL:D: Str() $str, :$scheduler = $*SCHEDULER) {
        self.write($str.encode($!enc), :$scheduler)
    }

    method write(IO::Socket::Async::SSL:D: Blob $b, :$scheduler = $*SCHEDULER) {
        start {
            $lib-lock.protect: {
                OpenSSL::SSL::SSL_write($!ssl, $b, $b.bytes);
                self!flush-read-bio();
            }
        }
    }

    method close(IO::Socket::Async::SSL:D: --> Nil) {
        $lib-lock.protect: {
            return if $!shutdown-promise;
            without $!shutdown-promise {
                $!shutdown-promise = Promise.new;
                self!handle-buffers();
            }
        }
        await $!shutdown-promise;
        $!sock.close;
        self!cleanup();
    }

    method DESTROY() {
        self!cleanup();
    }

    method !cleanup() {
        $lib-lock.protect: {
            if $!ssl {
                OpenSSL::SSL::SSL_free($!ssl);
                $!ssl = Nil;
            }
            if $!ctx {
                OpenSSL::Ctx::SSL_CTX_free($!ctx);
                $!ctx = Nil;
            }
        }
    }
}
