---
title: Post-Handshake Authentication in TLS
abbrev: TLS Post-Handshake Auth
docname: draft-sullivan-tls-post-handshake-auth-latest
date: 2016
category: std

ipr:
area: Security
workgroup: TLS
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: N. Sullivan
    name: Nick Sullivan
    organization: CloudFlare Inc.
    email: nick@cloudflare.com

 -
    ins: M. Thomson
    name: Martin Thomson
    organization: Mozilla
    email: martin.thomson@gmail.com

 -
    ins: M. Bishop
    name: Mike Bishop
    organization: Microsoft
    email: michael.bishop@microsoft.com

normative:
  RFC6066:
  RFC6961:
  RFC6962:
  I-D.ietf-tls-tls13:

informative:



--- abstract

This document describes a mechanism for performing post-handshake
certificate-based authentication in Transport Layer Security (TLS) versions 1.3
and later. This includes both spontaneous and elicited authentication of both
client and server.

--- middle

# Introduction

This document defines a way to authenticate one party of a Transport Layer
Security (TLS) communication to another using a certificate after the session
has been established. This allows both the client and server elicit proof of
ownership of additional identities at any time after the handshake has
completed. It also allows for both the client and server to spontaneously
provide a certificate and proof of ownership of the private key to the other
party.

This mechanism is useful in the following situations:

* servers that have the ability to serve requests from multiple domains over the
  same connection but do not have a certificate that is simultaneously
  authoritative over all of them

* servers that have resources that require client authentication to access and
  need to request client authentication after the connection has started

* clients that want to assert their identity to a server after a connection has
  been established

* clients that want a server to re-prove ownership of their private key during a
  connection

* clients that wish to ask a server to authenticate for a new domain not covered
  by the certificate included in the initial handshake

This document intends to replace the use of renegotiation for changing the
authentication of peers. It has an advantage over renegotiation in that it only
takes at most one round trip and it does not include an additional key exchange.

This document describes spontaneous and solicited modes for both client and
server authentication.  Support for each of these modes is negotiated using a
new `post_handshake_auth` extension.  New handshake messages are defined for use
after completion of the initial handshake, these mirror the authentication
messages that are used in the TLS 1.3 handshake.


# Post-Handshake Authentication TLS Extension

The `post_handshake_auth` TLS extension advertises support for post-handshake
authentication.

~~~
    enum {
        client_auth_elicited(0),
        client_auth_spontaneous(1),
        server_auth_elicited(2),
        server_auth_spontaneous(3),
        (255)
    } AuthTypes;

    struct {
        AuthType auth_types<0..2^8-1>;
        select (Role) {
            case server:
                SignatureScheme signature_algorithms<2..2^16-2>;
        }
    } PostHandshakeAuth;
~~~

The extension data for the `post_handshake_auth` extension is PostHandshakeAuth.

Each AuthType value represents support for a given authentication flow.

client_auth_elicited:
: indicates support for client authentication initiated by a server request

client_auth_spontaneous:
: indicates support for client authentication initiated by the client

server_auth_elicited:
: indicates support for server authentication initiated by a client request

server_auth_spontaneous:
: indicates support for server authentication initiated by the server

The client includes a `post_handshake_auth` extension containing every type of
authentication flow it supports in its ClientHello. The server replies with an
EncryptedExtensions containing a `post_handshake_auth` extension containing a
list of authentication types and the list of signature schemes supported. The
set of AuthTypes in the server’s `post_handshake_auth` extension MUST be a
subset of the set sent by the client. The extension MAY be omitted if the server
does not support any form of post-handshake authentication.

If a server supports either client_auth_elicited, or client_auth_spontaneous, it
must also include a "signature_algorithms" extension (defined in TLS 1.3 section
4.2.2.) containing a list of supported signature schemes. This contains a list
of the signature algorithms that the server is able to verify, listed in
descending order of preference.

## Post-Handshake Authentication Messages

The messages used for post-handshake authentication closely mirror those used to
authenticate certificates in the standard TLS handshake.

### Certificate Request

For elicited post-handshake authentication, the first message is used to define
the characteristics required in the elicited certificate.

~~~
    opaque DistinguishedName<1..2^16-1>;

    struct {
        opaque certificate_extension_oid<1..2^8-1>;
        opaque certificate_extension_values<0..2^16-1>;
    } CertificateExtension;

    struct {
        opaque certificate_request_context<0..2^8-1>;
        select (Role) {
            case server:
                DistinguishedName certificate_authorities<0..2^16-1>;
                CertificateExtension certificate_extensions<0..2^16-1>;
            case client:
                HostName host_name<1..2^16-1>;
        }
    } CertificateRequest;
~~~

The certificate_request_context is an opaque string which identifies the
certificate request and which will be echoed in the corresponding Certificate
message.

For CertificateRequests sent from the server, the DistinguishedName and
CertificateExtension fields are defined exactly as in the TLS 1.3
specification. For CertificateRequests send from the client, a HostName
containing the Server Name Indication (defined in [RFC6066]) used for
selecting the certificate is included.

### Certificate Message

The certificate message is used to transport the certificate. It mirrors the
Certificate message in the TLS with the addition of some certificate-specific
extensions.

~~~
    opaque ASN1Cert<1..2^24-1>;

    struct {
        opaque certificate_request_context<0..2^8-1>;
        ASN1Cert certificate_list<0..2^24-1>;
        Extension extensions<0..2^16-1>;
    } Certificate;
~~~

certificate_request_context:
: If this message is in response to a CertificateRequest, the value of
  certificate_request_context in that message.

certificate_list:
: This is a sequence (chain) of certificates. The sender's certificate MUST come
  first in the list. Each following certificate SHOULD directly certify one
  preceding it. Because certificate validation requires that trust anchors be
  distributed independently, a certificate that specifies a trust anchor MAY be
  omitted from the chain, provided that supported peers are known to possess any
  omitted certificates.

Valid extensions include OCSP Status extensions ([RFC6066] and [RFC6961]) and
SignedCertificateTimestamps ([RFC6962]). Any extension presented in a
Certificate message must only be presented if the associated ClientHello
extension was presented in the initial handshake.

The certificate_request_context is an opaque string that identifies the
certificate. If the certificate is used in response to a CertificateRequest, it
must mirror the certificate_request_context sent in the CertificateRequest. If
the Certificate message is part of an elicited authentication, the
certificate_request_context is chosen uniquely by the sender.

### CertificateVerify Message

The CertificateVerify message used in this document is defined in section
4.3.2. of the TLS 1.3 specification.

~~~
    struct {
        SignatureScheme algorithm;
        opaque signature<0..2^16-1>;
    } CertificateVerify;
~~~

The algorithm field specifies the signature algorithm used (see Section 4.2.2 of
TLS 1.3). The signature is a digital signature using that algorithm that covers
the hash output:

~~~
    Hash(Handshake Context + Certificate) + Hash(resumption_context)
~~~

The Handshake context and Base Key are defined in the following table:

| Mode | Handshake Context | Base Key |
|------|-------------------|----------|
| Spontaneous Authentication | ClientHello ... ClientFinished | traffic_secret_N |
| Elicited Authentication | ClientHello ... ClientFinished + CertificateRequest | traffic_secret_N |

### Finished Message

Finished is a MAC over the value

~~~
    Hash(Handshake Context + Certificate + CertificateVerify) +
        Hash(resumption_context)
~~~

The Finished messages uses a MAC key derived from the base key.

## Post-Handshake Authentication Flows

There are four post-handshake authentication exchanges.

### Elicited Client Authentication Flow

This flow is initiated by a CertificateRequest message from the server to the
client. It should only be sent if the server’s EncryptedExtensions contains a
ClientAuth extension with an odd-valued certificate_request_context. Upon
receiving a CertificateRequest message, the client may respond a contiguous
sequence:

Certificate, CertificateVerify, Finished

or the sequence:

Certificate, Finished

where the Certificate message has an empty certificate_list field. The
Certificate message must contain the same certificate_request_context as the
CertificateRequest message. Non-empty Certificate messages should conform to the
certificate_authorities and certificate_extensions sent in the
CertificateRequest.

~~~
        <- CertificateRequest
        -> Certificate, CertificateVerify, Finished
~~~

Because client authentication may require prompting the user, servers MUST be
prepared for some delay, including receiving an arbitrary number of other
messages between sending the CertificateRequest and receiving a response. In
addition, clients which receive multiple CertificateRequests in close succession
MAY respond to them in a different order than they were received (the
certificate_request_context value allows the server to disambiguate the
responses).

Any certificates provided by the client MUST be signed using a signature
algorithm found in the server's "signature_algorithms" extension. The end entity
certificate MUST allow the key to be used for signing (i.e., the
digitalSignature bit MUST be set if the Key Usage extension is present) with a
signature scheme indicated in the server’s "signature_algorithms" extension.

### Spontaneous Client Authentication Flow

This flow is initiated by a contiguous sequence of Certificate,
CertificateVerify, Finished message from the client to the server. The
Certificate message should contain an even-valued certificate_request_context so
as not to collide with an elicited client authentication. The Certificate
message should conform to the certificate_authorities and certificate_extensions
sent in the CertificateRequest and the SignatureSchemes presented in the
ClientAuth extension from the server’s EncryptedExtensions message.

~~~
        -> Certificate, CertificateVerify, Finished
~~~

Any certificates provided by the client MUST be signed using a signature
algorithm found in the server's "signature_algorithms" extension. The end entity
certificate MUST allow the key to be used for signing (i.e., the
digitalSignature bit MUST be set if the Key Usage extension is present) with a
signature scheme indicated in the server’s "signature_algorithms" extension.

### Elicited Server Authentication Flow

This flow is initiated by a CertificateRequest message from the client to the
server. The CertificateRequest should contain an odd-valued
certificate_request_context. Upon receiving a CertificateRequest message, the
server may respond with either a certificate with a contiguous sequence of:

Certificate, CertificateVerify, Finished

or the sequence:

Certificate, Finished

where the Certificate message has an empty certificate_list field. The
Certificate message must contain the same certificate_request_context as the
CertificateRequest message. The Certificate message should conform to the
ServerNameList sent in the CertificateRequest and the SignatureSchemes presented
in the ClientHello.

~~~
        -> CertificateRequest
        <- Certificate, CertificateVerify, Finished
~~~

Clients MUST be prepared for some delay, including receiving an arbitrary number
of other messages between sending the CertificateRequest and receiving a
response. In addition, servers which receive multiple CertificateRequests in
close succession MAY respond to them in a different order than they were
received (the certificate_request_context value allows the server to
disambiguate the responses).

### Spontaneous Server Authentication Flow

This flow is initiated by a contiguous sequence of Certificate,
CertificateVerify, Finished message from the server to the client. The
Certificate message should contain an even-valued certificate_request_context so
as not to collide with an elicited server authentication. The Certificate
message should conform to the SignatureSchemes presented in the ClientHello.

~~~
        <- Certificate, CertificateVerify, Finished
~~~

### Interaction With Resumption

Certificate identity should not be maintained across resumption. If a connection
is resumed, additional certificate identities for both client and server
certificates should be forgotten.

# Security Considerations

TBD

# Acknowledgements {#ack}

Eric Rescorla and Andrei Popov contributed to this draft.

--- back
