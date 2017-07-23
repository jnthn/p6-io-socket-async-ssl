use OpenSSL;
use OpenSSL::Bio;
use OpenSSL::Ctx;
use OpenSSL::EVP;
use OpenSSL::SSL;
use OpenSSL::Stack;

# XXX Contribute these back to the OpenSSL binding.
use OpenSSL::NativeLib;
use NativeCall;
sub BIO_new(OpenSSL::Bio::BIO_METHOD) returns OpaquePointer is native(&gen-lib) {*}
sub BIO_s_mem() returns OpenSSL::Bio::BIO_METHOD is native(&gen-lib) {*}
sub SSL_do_handshake(OpenSSL::SSL::SSL) returns int32 is native(&gen-lib) {*}
sub SSL_CTX_set_default_verify_paths(OpenSSL::Ctx::SSL_CTX) is native(&gen-lib) {*}
sub SSL_CTX_load_verify_locations(OpenSSL::Ctx::SSL_CTX, Str, Str) returns int32
    is native(&gen-lib) {*}
sub SSL_get_verify_result(OpenSSL::SSL::SSL) returns int32 is native(&gen-lib) {*}

my constant SSL_TLSEXT_ERR_OK = 0;
my constant SSL_TLSEXT_ERR_ALERT_FATAL = 2;
my constant SSL_TLSEXT_ERR_NOACK = 3;

my constant %VERIFY_FAILURE_REASONS = %(
     2 => 'unable to get issuer certificate',
     3 => 'unable to get certificate CRL',
     4 => 'unable to decrypt certificate\'s signature',
     5 => 'unable to decrypt CRL\'s signature',
     6 => 'unable to decode issuer public key',
     7 => 'certificate signature failure',
     8 => 'CRL signature failure',
     9 => 'certificate is not yet valid',
     10 => 'certificate has expired',
     11 => 'CRL is not yet valid',
     12 => 'CRL has expired',
     13 => 'format error in certificate\'s notBefore field',
     14 => 'format error in certificate\'s notAfter field',
     15 => 'format error in CRL\'s lastUpdate field',
     16 => 'format error in CRL\'s nextUpdate field',
     17 => 'out of memory',
     18 => 'self signed certificate',
     19 => 'self signed certificate in certificate chain',
     20 => 'unable to get local issuer certificate',
     21 => 'unable to verify the first certificate',
     22 => 'certificate chain too long',
     23 => 'certificate revoked',
     24 => 'invalid CA certificate',
     25 => 'path length constraint exceeded',
     26 => 'unsupported certificate purpose',
     27 => 'certificate not trusted',
     28 => 'certificate rejected',
     29 => 'subject issuer mismatch',
     30 => 'authority and subject key identifier mismatch',
     31 => 'authority and issuer serial number mismatch',
     32 => 'usage does not include certificate signing',
     50 => 'application verification failure',
);
sub SSL_get_peer_certificate(OpenSSL::SSL::SSL) returns Pointer is native(&gen-lib) {*}
sub X509_get_ext_d2i(Pointer, int32, CArray[int32], CArray[int32]) returns OpenSSL::Stack
    is native(&gen-lib) {*}
sub ASN1_STRING_to_UTF8(CArray[CArray[uint8]], Pointer) returns int32
    is native(&gen-lib) {*}

# ALPN
sub SSL_CTX_set_alpn_protos(OpenSSL::Ctx::SSL_CTX, Buf, uint32) returns int32
    is native(&gen-lib) {*}
sub SSL_CTX_set_alpn_select_cb(OpenSSL::Ctx::SSL_CTX, &callback (
                                   OpenSSL::SSL::SSL,        # ssl
                                   CArray[CArray[uint8]],    # out
                                   CArray[uint8],            # outlen
                                   CArray[uint8],            # in
                                   uint8,                    # inlen
                                   Pointer --> int32),       # arg
                               Pointer)
    is native(&gen-lib) {*}
sub SSL_get0_alpn_selected(OpenSSL::SSL::SSL, CArray[CArray[uint8]], uint32 is rw)
    is native(&gen-lib) {*}

my class GENERAL_NAME is repr('CStruct') {
    has int32 $.type;
    has Pointer $.data;
}
my enum GENERAL_NAME_TYPE <
    GEN_OTHERNAME GEN_EMAIL GEN_DNS GEN_X400 GEN_DIRNAME GEN_EDIPARTY
    GEN_URI GEN_IPADD GEN_RID
>;
my constant SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
my constant NID_subject_alt_name = 85;

# Per OpenSSL module, make a simple call to ensure libeay32.dll is loaded before
# ssleay32.dll on Windows.
OpenSSL::EVP::EVP_aes_128_cbc();

# On first load of the module, initialize the library.
OpenSSL::SSL::SSL_load_error_strings();
OpenSSL::SSL::SSL_library_init();

# For now, we'll put a lock around all of our interactions with the library.
# There are smarter things possible.
my $lib-lock = Lock.new;

class X::IO::Socket::Async::SSL is Exception {
    has Str $.message;
}
class X::IO::Socket::Async::SSL::Verification is X::IO::Socket::Async::SSL {}

class IO::Socket::Async::SSL {
    has IO::Socket::Async $!sock;
    has OpenSSL::Ctx::SSL_CTX $!ctx;
    has OpenSSL::SSL::SSL $!ssl;
    has $!read-bio;
    has $!write-bio;
    has $!connected-promise;
    has $!accepted-promise;
    has $!shutdown-promise;
    has $!closed;
    has $.enc;
    has $.insecure;
    has $!host;
    has $!alpn;
    has $.alpn-result;
    has Supplier::Preserving $!bytes-received .= new;
    has @!outstanding-writes;

    method new() {
        die "Cannot create an asynchronous SSL socket directly; please use\n" ~
            "IO::Socket::Async::SSL.connect or IO::Socket::Async::SSL.listen\n";
    }

    submethod BUILD(:$!sock, :$!enc, :$!ctx, :$!ssl, :$!read-bio, :$!write-bio,
                    :$!connected-promise, :$!accepted-promise, :$!host, :$!alpn,
                    :$!insecure = False) {
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
                   OpenSSL::ProtocolVersion :$version = -1,
                   :$ca-file, :$ca-path, :$insecure, :$alpn) {
        start {
            my $sock = await IO::Socket::Async.connect($host, $port, :$scheduler);
            my $connected-promise = Promise.new;
            $lib-lock.protect: {
                my $ctx = self!build-client-ctx($version);
                SSL_CTX_set_default_verify_paths($ctx);
                if defined($ca-file) || defined($ca-path) {
                    SSL_CTX_load_verify_locations($ctx,
                        defined($ca-file) ?? $ca-file.Str !! Str,
                        defined($ca-path) ?? $ca-path.Str !! Str);
                }
                if $alpn.defined {
                    my $buf = build-protocol-list(@$alpn);
                    SSL_CTX_set_alpn_protos($ctx, $buf, $buf.elems);
                }
                my $ssl = OpenSSL::SSL::SSL_new($ctx);
                my $read-bio = BIO_new(BIO_s_mem());
                my $write-bio = BIO_new(BIO_s_mem());
                check($ssl, OpenSSL::SSL::SSL_set_bio($ssl, $read-bio, $write-bio));
                OpenSSL::SSL::SSL_ctrl($ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, $host);
                OpenSSL::SSL::SSL_set_connect_state($ssl);
                check($ssl, SSL_do_handshake($ssl));
                CATCH {
                    OpenSSL::SSL::SSL_free($ssl) if $ssl;
                    OpenSSL::Ctx::SSL_CTX_free($ctx) if $ctx;
                }
                self.bless(
                    :$sock, :$enc, :$ctx, :$ssl, :$read-bio, :$write-bio,
                    :$connected-promise, :$host, :$insecure, :$alpn
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
                  :$certificate-file, :$private-key-file, :$alpn) {
        sub alpn-selector($ssl, $out, $outlen, $in, $inlen, $arg) {
            my $buf = Buf.new;
            for (0...$inlen-1) {
                $buf.push: $in[$_];
            }
            my $protos = parse-protocol-list($buf, $inlen);
            my $result;

            if $alpn ~~ Callable {
                $result = $alpn($protos);
            } else {
                return SSL_TLSEXT_ERR_NOACK if $alpn.elems == 0;
                for @$protos -> $p {
                    $alpn.map({ if ($_ eq $p) { $result = $p; } });
                    last if $result;
                }
            }

            return SSL_TLSEXT_ERR_ALERT_FATAL unless $result;
            $out[0] = CArray[uint8].new($result.encode('ascii').list);
            $outlen[0] = $result.chars;
            SSL_TLSEXT_ERR_OK;
        }

        supply {
            whenever IO::Socket::Async.listen($host, $port, :$scheduler) -> $sock {
                my $accepted-promise = Promise.new;
                $lib-lock.protect: {
                    my $ctx = self!build-server-ctx($version);
                    with $certificate-file {
                        OpenSSL::Ctx::SSL_CTX_use_certificate_file($ctx,
                            $certificate-file.Str, 1);
                    }
                    with $private-key-file {
                        OpenSSL::Ctx::SSL_CTX_use_PrivateKey_file($ctx,
                            $private-key-file.Str, 1);
                    }

                    if $alpn.defined {
                        SSL_CTX_set_alpn_select_cb(
                            $ctx,
                            &alpn-selector,
                            Pointer);
                    }
                    my $ssl = OpenSSL::SSL::SSL_new($ctx);
                    my $read-bio = BIO_new(BIO_s_mem());
                    my $write-bio = BIO_new(BIO_s_mem());
                    check($ssl, OpenSSL::SSL::SSL_set_bio($ssl, $read-bio, $write-bio));
                    OpenSSL::SSL::SSL_set_accept_state($ssl);
                    CATCH {
                        OpenSSL::SSL::SSL_free($ssl) if $ssl;
                        OpenSSL::Ctx::SSL_CTX_free($ctx) if $ctx;
                    }
                    self.bless(
                        :$sock, :$enc, :$ctx, :$ssl, :$read-bio, :$write-bio,
                        :$accepted-promise, :$alpn
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
                check($!ssl, $bytes-read);
            }
            with $!shutdown-promise {
                if check($!ssl, OpenSSL::SSL::SSL_shutdown($!ssl)) >= 0 {
                    self!flush-read-bio();
                    if @!outstanding-writes {
                        Promise.allof(@!outstanding-writes).then({
                            $!shutdown-promise.keep(True);
                        });
                    }
                    else {
                        $!shutdown-promise.keep(True);
                    }
                }
                else {
                    self!flush-read-bio();
                }
            }
            CATCH {
                default {
                    $!bytes-received.quit($_);
                }
            }
        }
        orwith $!connected-promise {
            if check($!ssl, OpenSSL::SSL::SSL_connect($!ssl), 1) > 0 {
                # ALPN check
                if $!alpn.defined && $!alpn-result !~~ Nil|Buf {
                    self!check-alpn(:client);
                } else {
                    $!alpn-result := Nil;
                }
                if $!insecure {
                    $!connected-promise.keep(self) if $!connected-promise.status ~~ Planned;
                }
                else {
                    my $cert = SSL_get_peer_certificate($!ssl);
                    if $cert {
                        if self!hostname-mismatch($cert) -> $message {
                            $!connected-promise.break(X::IO::Socket::Async::SSL::Verification.new(
                                :$message
                            ));
                        }
                        elsif (my $verify = SSL_get_verify_result($!ssl)) == 0 {
                            $!connected-promise.keep(self);
                        }
                        else {
                            my $reason = %VERIFY_FAILURE_REASONS{$verify} // 'unknown failure';
                            $!connected-promise.break(X::IO::Socket::Async::SSL::Verification.new(
                                message => "Server certificate verification failed: $reason"
                            ));
                        }
                    }
                    else {
                        $!connected-promise.break(X::IO::Socket::Async::SSL::Verification.new(
                            message => 'Server did not provide a certificate to verify'
                        ));
                    }
                }
            }
            self!flush-read-bio();
            CATCH {
                default {
                    if $!connected-promise {
                        $!bytes-received.quit($_);
                    }
                    else {
                        $!connected-promise.break($_);
                    }
                }
            }
        }
        orwith $!accepted-promise {
            if check($!ssl, OpenSSL::SSL::SSL_accept($!ssl)) >= 0 {
                # ALPN
                if $!alpn.defined && $!alpn-result !~~ Nil|Buf {
                    self!check-alpn(:server);
                } else {
                    $!alpn-result := Nil;
                }
                $!accepted-promise.keep(self) if $!accepted-promise.status ~~ Planned;
            }
            self!flush-read-bio();
            CATCH {
                default {
                    if $!accepted-promise {
                        $!bytes-received.quit($_);
                    }
                    else {
                        $!accepted-promise.break($_) if $!accepted-promise.status ~~ Planned;
                    }
                }
            }
        }
    }

    method !check-alpn(:$client, :$server) {
        my $protocol = CArray[CArray[uint8]].new;
        $protocol[0] = CArray[uint8].new;
        my int32 $len;
        SSL_get0_alpn_selected($!ssl, $protocol, $len);
        if $len == 0 {
            $!accepted-promise.break if $server;
            $!alpn-result = Nil if $client;
        } else {
            for (0...$len-1) {
                $!alpn-result ~= chr($protocol[0][$_]);
            }
        }
    }

    method !flush-read-bio(--> Nil) {
        my $buf = Buf.allocate(32768);
        while OpenSSL::Bio::BIO_read($!write-bio, $buf, 32768) -> $bytes-read {
            last if $bytes-read < 0;
            my $p = $!sock.write($buf.subbuf(0, $bytes-read));
            @!outstanding-writes.push($p);
            $p.then: {
                $lib-lock.protect: {
                    @!outstanding-writes .= grep({ $_ !=== $p });
                }
            }
        }
    }

    method !hostname-mismatch($cert) {
        my $altnames = X509_get_ext_d2i($cert, NID_subject_alt_name, CArray[int32], CArray[int32]);
        my $fold-host = $!host.fc;
        if ($altnames) {
            my @no-match;
            loop (my int $i = 0; $i < $altnames.num; $i++) {
                my $gd = nativecast(GENERAL_NAME, $altnames.data[$i]);
                my $out = CArray[CArray[uint8]].new;
                $out[0] = CArray[uint8];
                my $name-bytes = ASN1_STRING_to_UTF8($out, $gd.data);
                my $name = Buf.new($out[0][^$name-bytes]).decode('utf-8');
                given $gd.type {
                    when GEN_DNS {
                        my $fold-name = $name.fc;
                        return if $fold-name eq $fold-host ||
                                  wildcard-match($fold-name, $fold-host);
                        push @no-match, $name;
                    }
                    # TODO IP address case
                }
            }
            if @no-match {
                return "Host $!host does not match any subject alt name on the " ~
                    "certificate (@no-match.join(', '))";
            }
        }
        else {
            # TODO Common names fallback
            return "Certificate contains no altnames to check host against";
        }
        Nil
    }

    # Implements the rules from RFC 6125 section 6.4.3.
    sub wildcard-match($name, $host) {
        return False without $name.index('*');
        my ($name-wild, $rest-name) = $name.split('.', 2);
        my ($host-wild, $rest-host) = $host.split('.', 2);
        return False unless $rest-name eq $rest-host;
        if $name-wild eq '*' {
            return True;
        }
        elsif $host-wild.chars < $name-wild.chars - 1 {
            # fo*od can match foxod or food but never fod.
            return False;
        }
        elsif $name-wild ~~ /^ (<-[*]>*) '*' (<-[*]>*) $/ {
            return $host-wild.starts-with(~$0) &&
                   $host-wild.ends-with(~$1);
        }
        return False;
    }

    sub parse-protocol-list($array, $len --> List) {
        my @result;
        my $names = $array;
        my $rest = $len;
        while $rest {
            my $size = $names[0];
            @result.push: $names.subbuf(1, $size).decode;
            $names .= subbuf($size+1);
            $rest -= $size + 1;
        }
        @result;
    }

    sub build-protocol-list(@protocols --> Buf) {
        my $list = Buf.new;
        for @protocols -> $p {
            $list.push: $p.chars;
            $list.push: $p.encode('ascii')
        }
        $list;
    }

    my constant SSL_ERROR_WANT_READ = 2;
    my constant SSL_ERROR_WANT_WRITE = 3;
    sub check($ssl, $rc, $expected = 0) {
        if $rc < $expected {
            my $error = OpenSSL::SSL::SSL_get_error($ssl, $rc);
            unless $error == any(SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE) {
                die X::IO::Socket::Async::SSL.new(
                    message => OpenSSL::Err::ERR_error_string($error, Nil)
                );
            }
        }
        $rc
    }

    method Supply(:$bin, :$enc = $!enc, :$scheduler = $*SCHEDULER) {
        if $bin {
            $!bytes-received.Supply.schedule-on($scheduler)
        }
        else {
            supply {
                my $norm-enc = Rakudo::Internals.NORMALIZE_ENCODING($enc // 'utf-8');
                my $dec = Encoding::Registry.find($norm-enc).decoder();
                whenever $!bytes-received.Supply.schedule-on($scheduler) {
                    $dec.add-bytes($_);
                    emit $dec.consume-available-chars();
                    LAST emit $dec.consume-all-chars();
                }
            }
        }
    }

    method print(IO::Socket::Async::SSL:D: Str() $str, :$scheduler = $*SCHEDULER) {
        self.write($str.encode($!enc // 'utf-8'), :$scheduler)
    }

    method write(IO::Socket::Async::SSL:D: Blob $b, :$scheduler = $*SCHEDULER) {
        $lib-lock.protect: {
            if $!closed {
                my $p = Promise.new;
                $p.break(X::IO::Socket::Async::SSL.new(
                    message => 'Cannot write to closed socket'
                ));
                return $p;
            }
            my $p = start {
                $lib-lock.protect: {
                    OpenSSL::SSL::SSL_write($!ssl, $b, $b.bytes);
                    self!flush-read-bio();
                    # The following doesn't race on $p assignment due to the
                    # holding of $lib-lock in the code with the assignment.
                    @!outstanding-writes .= grep({ $_ !=== $p });
                }
            }
            @!outstanding-writes.push($p);
            $p
        }
    }

    method close(IO::Socket::Async::SSL:D: --> Nil) {
        my @wait-writes;
        $lib-lock.protect: {
            $!closed = True;
            if @!outstanding-writes {
                @wait-writes = @!outstanding-writes;
            }
            else {
                return if $!shutdown-promise;
                without $!shutdown-promise {
                    $!shutdown-promise = Promise.new;
                    self!handle-buffers();
                }
            }
        }
        if @wait-writes {
            Promise.allof(@wait-writes).then({ self.close });
        }
        else {
            await $!shutdown-promise;
            $!sock.close;
            self!cleanup();
        }
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
