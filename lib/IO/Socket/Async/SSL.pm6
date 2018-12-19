use OpenSSL;
use OpenSSL::Bio;
use OpenSSL::Ctx;
use OpenSSL::EVP;
use OpenSSL::X509;
use OpenSSL::SSL;
use OpenSSL::Stack;
use OpenSSL::Err;

# XXX Contribute these back to the OpenSSL binding.
use OpenSSL::NativeLib;
use NativeCall;
sub BIO_new(OpenSSL::Bio::BIO_METHOD) returns OpaquePointer is native(&gen-lib) {*}
sub BIO_s_mem() returns OpenSSL::Bio::BIO_METHOD is native(&gen-lib) {*}
sub SSL_do_handshake(OpenSSL::SSL::SSL) returns int32 is native(&ssl-lib) {*}
sub SSL_CTX_set_default_verify_paths(OpenSSL::Ctx::SSL_CTX) is native(&ssl-lib) {*}
sub SSL_CTX_load_verify_locations(OpenSSL::Ctx::SSL_CTX, Str, Str) returns int32
    is native(&ssl-lib) {*}
sub SSL_get_verify_result(OpenSSL::SSL::SSL) returns int32 is native(&ssl-lib) {*}
sub SSL_CTX_set_cipher_list(OpenSSL::Ctx::SSL_CTX, Str) returns int32
    is native(&ssl-lib) {*}

sub d2i_PKCS12(Pointer, CArray[CArray[uint8]], long) returns Pointer is native(&gen-lib) {*}
sub PKCS12_parse(Pointer, Str, CArray[Pointer], CArray[Pointer], CArray[Pointer])
    returns int32 is native(&gen-lib) {*}

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
sub SSL_get_peer_certificate(OpenSSL::SSL::SSL) returns Pointer is native(&ssl-lib) {*}
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
my constant SSL_CTRL_SET_TMP_DH = 3;
my constant SSL_CTRL_SET_TMP_ECDH = 4;
my constant SSL_CTRL_OPTIONS = 32;
my constant SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
my constant NID_subject_alt_name = 85;

my constant SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x10000;
my constant SSL_OP_NO_COMPRESSION = 0x20000;
my constant SSL_OP_CIPHER_SERVER_PREFERENCE = 0x400000;

# DH setup-related bits, so we can use ciphers that need this
my constant BIGNUM = Pointer;
my class DH is repr('CStruct') {
    has int32 $.pad;
    has int32 $.version;
    has BIGNUM $.p;
    has BIGNUM $.g;
    has int32 $.length is rw;
    # There are more fields in this struct, but we don't care about them in this
    # module.

    method set-p(\p) { $!p := p }
    method set-g(\g) { $!g := g }
};
sub DH_new() returns DH is native(&gen-lib) {*}
sub DH_free(DH) is native(&gen-lib) {*}
sub BN_bin2bn(Blob, int32, BIGNUM) returns BIGNUM is native(&gen-lib) {*}
sub SSL_CTX_ctrl_DH(OpenSSL::Ctx::SSL_CTX, int32, int32, DH) is symbol('SSL_CTX_ctrl')
    returns int32 is native(&ssl-lib) {*}
sub get_dh1024() returns DH {
    # Based on output from `openssl dhparam -dsaparam -C 512`
    my constant dh1024_p = Blob.new:
        0xC7,0xA6,0x29,0x3B,0x29,0x3F,0x9B,0x94,0x96,0x23,0x9B,0x79,
        0xDF,0xC9,0x9C,0x2D,0xF0,0x7C,0x04,0xC0,0x81,0xC8,0x08,0xF4,
        0x7B,0xD4,0x76,0xAB,0xFF,0x07,0x6C,0x9A,0xE9,0xF1,0x08,0x7F,
        0xBB,0x32,0xF0,0x7E,0xC7,0xD7,0xA2,0xA9,0x9A,0x1E,0xD1,0x84,
        0x9E,0xEB,0xEA,0x88,0x72,0x1D,0xF5,0x61,0x83,0xA9,0x7B,0xE4,
        0x1F,0xA0,0xA6,0x01,0x82,0xD1,0x6C,0x6F,0xB2,0x15,0x20,0x50,
        0x70,0xDB,0xEE,0x31,0x5E,0x69,0xF7,0x2F,0x0D,0xE5,0x55,0x8C,
        0xF7,0xE3,0x5F,0x71,0x58,0x3F,0xEA,0x9C,0xE0,0xE9,0x26,0x2E,
        0x21,0xF1,0xB9,0x3A,0xBA,0x5A,0x03,0xBB,0x1C,0x35,0xF0,0xA0,
        0xF2,0x06,0x1A,0xB3,0x30,0xFB,0x39,0x22,0xDA,0x15,0x38,0xFC,
        0x21,0x20,0x91,0xDD,0x5B,0xC1,0x16,0x9B;
    my constant dh1024_g = Blob.new:
        0x19,0x4F,0x37,0x25,0x31,0xD6,0x79,0xE9,0x00,0xA9,0x70,0x8A,
        0x0E,0x60,0xB5,0x30,0x2B,0x7F,0x53,0x9A,0x06,0xB0,0x9D,0xD3,
        0x58,0x83,0xFF,0xAE,0x3F,0xAC,0xD3,0xFC,0x56,0xC2,0x64,0xA7,
        0x96,0x7C,0xC2,0x89,0x8C,0x97,0x96,0xB5,0xC2,0x02,0x3A,0x4A,
        0x94,0x6A,0xD3,0x99,0x2D,0x72,0x07,0xD4,0x53,0x3D,0x98,0x38,
        0x74,0x96,0x32,0x4A,0xC9,0x85,0x86,0x0D,0x8B,0xD3,0xE8,0x79,
        0xE1,0x00,0xEF,0x01,0x27,0xEA,0xFA,0xCF,0x9D,0x2C,0x7A,0xC9,
        0x18,0x14,0x1C,0x34,0xAD,0x53,0x37,0x01,0x09,0xB8,0x7F,0x5E,
        0x92,0x4D,0xCB,0xDA,0x29,0x0D,0xA4,0x5E,0x06,0xE4,0x1B,0xC8,
        0x3F,0x7F,0x60,0x6B,0x82,0x8F,0x48,0x59,0xED,0x3D,0x63,0xE8,
        0x9C,0xF0,0xB6,0x42,0xBF,0xFD,0xD9,0x32;
    my DH $dh = DH_new();
    without $dh {
        fail("Could not allocate DH");
    }
    $dh.set-p: BN_bin2bn(dh1024_p, dh1024_p.elems, BIGNUM);
    $dh.set-g: BN_bin2bn(dh1024_g, dh1024_g.elems, BIGNUM);
    if !$dh.p || !$dh.g {
        DH_free($dh);
        fail("Failed to set up DH");
    }
    $dh.length = 160;
    return $dh;
}

# ECDH setup
my constant EC_KEY = Pointer;
my constant EC_GROUP = Pointer;
my constant NID_X9_62_prime256v1 = 415;
sub EC_KEY_new() returns EC_KEY is native(&gen-lib) {*}
sub EC_KEY_set_group(EC_KEY, EC_GROUP) returns int32 is native(&gen-lib) {*}
sub EC_GROUP_new_by_curve_name(int32) returns EC_GROUP is native(&gen-lib) {*}
sub SSL_CTX_ctrl_ECDH(OpenSSL::Ctx::SSL_CTX, int32, int32, EC_KEY) is symbol('SSL_CTX_ctrl')
    returns int32 is native(&ssl-lib) {*}
sub get_ecdh() {
    my $ecdh = EC_KEY_new();
    without $ecdh {
        fail("Failed to allocate ECDH key");
    }
    if EC_KEY_set_group($ecdh, EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) != 1 {
        fail("Failed to set ECDH curve group");
    }
    return $ecdh;
}

# Per OpenSSL module, make a simple call to ensure libeay32.dll is loaded before
# ssleay32.dll on Windows.
OpenSSL::EVP::EVP_aes_128_cbc();

# On first load of the module, initialize the library.
try {
    CATCH {
        default { OpenSSL::SSL::OPENSSL_init_ssl(0, OpaquePointer); }
    }
    OpenSSL::SSL::SSL_library_init();
    OpenSSL::SSL::SSL_load_error_strings();
}

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

    submethod BUILD(:$!sock, :$!enc, OpenSSL::Ctx::SSL_CTX :$!ctx, :$!ssl,
                    :$!read-bio, :$!write-bio,
                    :$!connected-promise, :$!accepted-promise, :$!host, :$!alpn,
                    :$!insecure = False) {
        $!sock.Supply(:bin).tap:
            -> Blob $data {
                $lib-lock.protect: {
                    if $!ssl {
                        OpenSSL::Bio::BIO_write($!read-bio, $data, $data.bytes);
                        self!handle-buffers();
                    }
                }
            },
            done => {
                $lib-lock.protect: -> {
                    self!handle-buffers();
                    with $!connected-promise {
                        if .status == Planned {
                            .break: X::IO::Socket::Async::SSL.new:
                                message => 'The socket was closed during negotiation';
                        }
                    }
                }
                $!bytes-received.done;
            },
            quit => {
                $!bytes-received.quit($_);
            };
        self!handle-buffers();
    }

    method connect(
		IO::Socket::Async::SSL:U:
		Str() $host,
		Int() $port,
		:$enc = 'utf8',
		:$scheduler = $*SCHEDULER,
		OpenSSL::ProtocolVersion :$version = -1,
		:$ca-file,
		:$ca-path,
		:$insecure,
		:$alpn,
		Str :$ciphers,
		:$certificate-file,
	) {
        self!client-setup:
            { IO::Socket::Async.connect($host, $port, :$scheduler) },
            :$enc, :$version, :$ca-file, :$ca-path, :$insecure,
            :$alpn, :$ciphers, :$host, :$certificate-file;
     }

    method upgrade-client(IO::Socket::Async::SSL:U: IO::Socket::Async:D $conn,
                          :$enc = 'utf8', OpenSSL::ProtocolVersion :$version = -1,
                          :$ca-file, :$ca-path, :$insecure, :$alpn,
                          Str :$ciphers, Str :$host) {
        self!client-setup:
            { Promise.kept($conn) },
            :$enc, :$version, :$ca-file, :$ca-path, :$insecure,
            :$alpn, :$ciphers, :$host;
	}

    method !client-setup(
		&connection-source,
		:$enc = 'utf8',
		OpenSSL::ProtocolVersion :$version,
		:$ca-file,
		:$ca-path,
		:$insecure,
		:$alpn,
		:$ciphers,
		Str :$host,
		:$certificate-file,
	) {
        start {
            my $sock = await connection-source();
            my $connected-promise = Promise.new;
            $lib-lock.protect: {
                my $ctx = self!build-client-ctx($version);
                SSL_CTX_set_default_verify_paths($ctx);
                if defined($ca-file) || defined($ca-path) {
                    SSL_CTX_load_verify_locations($ctx,
                        defined($ca-file) ?? $ca-file.Str !! Str,
                        defined($ca-path) ?? $ca-path.Str !! Str);
                }
                with $ciphers {
                    if SSL_CTX_set_cipher_list($ctx, $ciphers) == 0 {
                        die "No ciphers from the provided list were selected";
                    }
                }

				self!use-certificate-file($_, $ctx) with $certificate-file;

                if $alpn.defined {
                    my $buf = build-protocol-list(@$alpn);
                    SSL_CTX_set_alpn_protos($ctx, $buf, $buf.elems);
                }
                my $ssl = OpenSSL::SSL::SSL_new($ctx);
                my $read-bio = BIO_new(BIO_s_mem());
                my $write-bio = BIO_new(BIO_s_mem());
                check($ssl, OpenSSL::SSL::SSL_set_bio($ssl, $read-bio, $write-bio));
                with $host {
                    OpenSSL::SSL::SSL_ctrl($ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, $host);
                }
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
                  :$certificate-file, :$private-key-file, :$alpn,
                  Str :$ciphers, :$prefer-server-ciphers, :$no-compression,
                  :$no-session-resumption-on-renegotiation) {
        self!server-setup:
            IO::Socket::Async.listen($host, $port, :$scheduler),
            :$enc, :$version, :$certificate-file, :$private-key-file,
            :$alpn, :$ciphers, :$prefer-server-ciphers, :$no-compression,
            :$no-session-resumption-on-renegotiation;
    }

    method upgrade-server(IO::Socket::Async::SSL:U: IO::Socket::Async:D $socket,
                  :$enc = 'utf8', OpenSSL::ProtocolVersion :$version = -1,
                  :$certificate-file, :$private-key-file, :$alpn,
                  Str :$ciphers, :$prefer-server-ciphers, :$no-compression,
                  :$no-session-resumption-on-renegotiation) {
        self!server-setup:
            $socket,
            :$enc, :$version, :$certificate-file, :$private-key-file,
            :$alpn, :$ciphers, :$prefer-server-ciphers, :$no-compression,
            :$no-session-resumption-on-renegotiation;
    }

    method !server-setup($connection-source,
                  :$enc, OpenSSL::ProtocolVersion :$version,
                  :$certificate-file, :$private-key-file, :$alpn,
                  Str :$ciphers, :$prefer-server-ciphers, :$no-compression,
                  :$no-session-resumption-on-renegotiation) {
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
            # Build context, which we'll share between connections.
            my $ctx;
            $lib-lock.protect: {
                $ctx = self!build-server-ctx($version);
                my ($have-cert, $have-pkey);

				$have-cert = self!use-certificate-file($_, $ctx) with $certificate-file;

                with $private-key-file {
                    die "Private key already added as $have-pkey" with $have-pkey;
                    OpenSSL::Ctx::SSL_CTX_use_PrivateKey_file($ctx,
                        $private-key-file.Str, 1);
                }
                with get_dh1024() {
                    if SSL_CTX_ctrl_DH($ctx, SSL_CTRL_SET_TMP_DH, 0, $_) == 0 {
                        warn "IO::Socket::Async::SSL: Failed to set temporary DH";
                    }
                }
                else {
                    warn "IO::Socket::Async::SSL: Failed to create DH";
                }
                with get_ecdh() {
                    if SSL_CTX_ctrl_ECDH($ctx, SSL_CTRL_SET_TMP_ECDH, 0, $_) == 0 {
                        warn "IO::Socket::Async::SSL: Failed to set temporary ECDH";
                    }
                }
                else {
                    warn "IO::Socket::Async::SSL: Failed to create ECDH";
                }
                with $ciphers {
                    if SSL_CTX_set_cipher_list($ctx, $ciphers) == 0 {
                        die "No ciphers from the provided list were selected";
                    }
                }
                if $prefer-server-ciphers {
                    OpenSSL::Ctx::SSL_CTX_ctrl($ctx, SSL_CTRL_OPTIONS,
                        SSL_OP_CIPHER_SERVER_PREFERENCE, Str);
                }
                if $no-compression {
                    OpenSSL::Ctx::SSL_CTX_ctrl($ctx, SSL_CTRL_OPTIONS,
                        SSL_OP_NO_COMPRESSION, Str);
                }
                if $no-session-resumption-on-renegotiation {
                    OpenSSL::Ctx::SSL_CTX_ctrl($ctx, SSL_CTRL_OPTIONS,
                        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION, Str);
                }

                if $alpn.defined {
                    SSL_CTX_set_alpn_select_cb(
                        $ctx,
                        &alpn-selector,
                        Pointer);
                }
            }

            CLOSE {
                if $ctx {
                    OpenSSL::Ctx::SSL_CTX_free($ctx);
                    $ctx = Nil;
                }
            }

            if $connection-source ~~ Supply {
                whenever $connection-source -> $sock {
                    handle-connection($sock);
                }
            }
            else {
                handle-connection($connection-source);
            }

            sub handle-connection($sock) {
                my $accepted-promise = Promise.new;
                $lib-lock.protect: {
                    my $ssl = OpenSSL::SSL::SSL_new($ctx);
                    my $read-bio = BIO_new(BIO_s_mem());
                    my $write-bio = BIO_new(BIO_s_mem());
                    check($ssl, OpenSSL::SSL::SSL_set_bio($ssl, $read-bio, $write-bio));
                    OpenSSL::SSL::SSL_set_accept_state($ssl);
                    CATCH {
                        .note;
                        OpenSSL::SSL::SSL_free($ssl) if $ssl;
                        OpenSSL::Ctx::SSL_CTX_free($ctx) if $ctx;
                    }
                    self.bless(
                        :$sock, :$enc, :$ssl, :$read-bio, :$write-bio,
                        :$accepted-promise, :$alpn
                    )
                }
                whenever $accepted-promise -> $ssl-socket {
                    emit $ssl-socket;
                    QUIT {
                        default {
                            # If the handshake failed, drop the connection.
                            $sock.close;
                        }
                    }
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
        if !$!ssl {
            # Connection no longer active; don't do anything.
        }
        elsif $!connected-promise || $!accepted-promise {
            loop {
                my $buf = buf8.allocate(32768);
                my $bytes-read = OpenSSL::SSL::SSL_read($!ssl, $buf, 32768);
                if $bytes-read > 0 {
                    $!bytes-received.emit($buf.subbuf(0, $bytes-read));
                }
                elsif $bytes-read == 0 {
                    last;
                }
                else {
                    check($!ssl, $bytes-read);
                    last;
                }
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
                    self!check-alpn;
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
                    self!check-alpn;
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

    method !check-alpn() {
        my $protocol = CArray[CArray[uint8]].new;
        $protocol[0] = CArray[uint8].new;
        my int32 $len;
        SSL_get0_alpn_selected($!ssl, $protocol, $len);
        if $len == 0 {
            $!alpn-result = Nil;
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
            my $error = OpenSSL::Err::ERR_get_error();
            my @log;
            while ($error != 0|SSL_ERROR_WANT_READ|SSL_ERROR_WANT_WRITE) {
                @log.push(OpenSSL::Err::ERR_error_string($error, Nil));
                $error = OpenSSL::Err::ERR_get_error();
            }
            if @log.elems != 0 {
                die X::IO::Socket::Async::SSL.new(
                    message => @log.join("\n")
                )
            }
        }
        $rc
    }

    method Supply(:$bin, :$enc = $!enc, :$scheduler = $*SCHEDULER) {
        if $bin {
            $!bytes-received.Supply.Channel.Supply
        }
        else {
            supply {
                my $norm-enc = Rakudo::Internals.NORMALIZE_ENCODING($enc // 'utf-8');
                my $dec = Encoding::Registry.find($norm-enc).decoder();
                whenever $!bytes-received.Supply.Channel.Supply {
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

    method peer-host() {
        $!sock.peer-host;
    }
    method peer-port() {
        $!sock.peer-port;
    }
    method socket-host() {
        $!sock.socket-host;
    }
    method socket-port() {
        $!sock.socket-port;
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

    method supports-alpn() {
        once so try {
            my $ctx = self!build-client-ctx(-1);
            my $buf = build-protocol-list(['h2']);
            SSL_CTX_set_alpn_protos($ctx, $buf, $buf.elems);
            LEAVE OpenSSL::Ctx::SSL_CTX_free($ctx) if $ctx;
            True
        }
    }

    method DESTROY() {
        self!cleanup();
    }

    method !cleanup() {
        if $!ssl || $!ctx {
            start $lib-lock.protect: {
                if $!ssl {
                    OpenSSL::SSL::SSL_free($!ssl);
                    $!ssl = Nil;
                }
                if $!ctx {
                    OpenSSL::Ctx::SSL_CTX_free($!ctx);
                    $!ctx = Nil;
                }
                $!read-bio = Nil;
                $!write-bio = Nil;
            }
        }
    }

	method !use-certificate-file (
		Str() $certificate-file,
		$ctx is rw,
	) {
		if (OpenSSL::Ctx::SSL_CTX_use_certificate_chain_file($ctx, $certificate-file) == 1) {
			return 'PEM';
		}

		if (OpenSSL::Ctx::SSL_CTX_use_certificate_file($ctx, $certificate-file, 2) == 1) {
			return 'DER';
		}

		# Failed to import either PEM chain or ASN1 certificate file
		# Proceeding with PKCS12
		my $p12buf = $certificate-file.IO.slurp(:bin);
		my Pointer $pkcs12 = d2i_PKCS12(
			Pointer,
			CArray[CArray[uint8]].new([CArray[uint8].new($p12buf)]),
			$p12buf.elems
		);

		die "Failed to import $certificate-file as PEM/ASN1/PKCS12" unless so $pkcs12;

		my $pkey = CArray[Pointer].new([Pointer.new]);
		my $cert = CArray[Pointer].new([Pointer.new]);
		my $chain = CArray[Pointer].new([Pointer.new]);

		# TODO: Passphrase handling
		my $pkcs12-parse = PKCS12_parse($pkcs12, '', $pkey, $cert, $chain) == 1;

		die "Failed to parse $certificate-file as PKCS12" unless $pkcs12-parse;

		#if ($pkey[0]) {
		#	$have-pkey = 'PKCS12';
		#	OpenSSL::Ctx::SSL_CTX_use_PrivateKey($ctx, $pkey[0]);
		#	OpenSSL::EVP::EVP_PKEY_free($pkey[0]);
		#}

		die "No server certificate in $certificate-file" unless $cert[0];

		OpenSSL::Ctx::SSL_CTX_use_certificate($ctx, $cert[0]);
		OpenSSL::X509::X509_free($cert[0]);

		if ($chain[0]) {
			for (0..OpenSSL::Stack::sk_num(nativecast(OpenSSL::Stack, $chain[0]))) {
				my $x509 = OpenSSL::Stack::sk_value(nativecast(OpenSSL::Stack, $chain[0]), $_);

				if ($x509) {
					OpenSSL::Ctx::SSL_CTX_ctrl($ctx, 14, 0, $x509);
				}
			}

			OpenSSL::Stack::sk_free(nativecast(OpenSSL::Stack, $chain[0]));
		}


		return 'PKCS12';
	}
}
