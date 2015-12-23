---
title: Reactive Certificate-Based Client Authentication in HTTP/2
abbrev: HTTP/2 Client Certs
docname: draft-thomson-http2-client-certs-latest
date: 2015
category: std

ipr: trust200902
area: General
workgroup: HTTP
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
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
  RFC2119:
  RFC5705:
  RFC5246:
  RFC5280:
  RFC7230:
  RFC7540:
  X690:
    target: http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
    title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
    author:
        org: ITU-T
    date: 2002
    seriesinfo:
        ISO: ISO/IEC 8825-1:2002
  I-D.ietf-tls-tls13:

informative:



--- abstract

Some HTTP servers provide a subset of resources that require additional
authentication to interact with.  HTTP/1.1 servers rely on TLS renegotiation
that is triggered by a request to a protected resource.  HTTP/2 made this
pattern impossible by forbidding the use of TLS renegotiation.  While TLS 1.3
provides an alternate mechanism to obtain client certificates, this mechanism
does not map well to usage in TLS 1.2.

This document describes a how client authentication might be requested by a
server as a result of receiving a request to a protected resource.

--- middle

# Introduction

Many existing HTTP [RFC7230] servers have different authentication requirements
for the different resources they serve.  Of the bountiful authentication options
available for authenticating HTTP requests, client certificates present a unique
challenge for resource-specific authentication requirements because of the
interaction with the underlying TLS [RFC5246][I-D.ietf-tls-tls13] layer.

For servers that wish to use client certificates to authenticate users, they
might request client authentication during or immediately after the TLS handshake.
However, if not all users or resources need certificate-based authentication,
a request for a certificate has the unfortunate consequence of triggering the
client to seek a certificate.  Such a request can result in a poor experience,
particularly when sent to a client that does not expect the request.

The TLS 1.3 CertificateRequest can be used by servers to give clients hints about
which certificate to offer.  Servers that rely on certificate-based
authentication might request different certificates for different resources.
Such a server cannot use contextual information about the resource to construct
an appropriate TLS CertificateRequest message during the initial handshake.

Consequently, client certificates are requested at connection establishment time
only in cases where all clients are expected or required to have a single
certificate that is used for all resources.  Many other uses for client
certificates are reactive, that is, certificates are requested in response to
the client making a request.

In Yokohama, there was extensive working group discussion regarding why certificate
authentication could not easily be done at the HTTP semantic layer.  However, in
subsequent discussion, it became apparent that the HTTP *framing* layer did not
suffer from the same limitation.

In this document, a mechanism for doing certificate-based client authentication
via HTTP/2 frames is defined.  This mechanism can be implemented at the HTTP layer
without requiring new TLS stack behavior and without breaking the existing interface
between HTTP and applications which employ client certificates.

## Reactive Certificate Authentication in HTTP/1.1

### Using TLS 1.2 and previous

In HTTP/1.1, a server that relies on client authentication for a subset of users
or resources does not request a certificate when the connection is established.
Instead, it only requests a client certificate when a request is made to a
resource that requires a certificate.  TLS 1.2 [RFC5246] accomodates this
by permitting the server to request a new TLS handshake, in which the server
will request the client's certificate.

{{ex-http11}} shows the server initiating a TLS-layer renegotiation in response
to receiving an HTTP/1.1 request to a protected resource.

~~~
Client                                      Server
   -- (HTTP) GET /protected -------------------> *1
   <---------------------- (TLS) HelloRequest -- *2
   -- (TLS) ClientHello ----------------------->
   <------------------ (TLS) ServerHello, ... --
   <---------------- (TLS) CertificateRequest -- *3
   -- (TLS) ..., Certificate ------------------> *4
   -- (TLS) Finished -------------------------->
   <-------------------------- (TLS) Finished --
   <--------------------------- (HTTP) 200 OK -- *5
~~~
{: #ex-http11 title="HTTP/1.1 Reactive Certificate Authentication with TLS 1.2"}

In this example, the server receives a request for a protected resource (at \*1
on {{ex-http11}}).  Upon performing an authorization check, the server
determines that the request requires authentication using a client certificate
and that no such certificate has been provided.

The server initiates TLS renegotiation by sending a TLS HelloRequest (at \*2).
The client then initiates a TLS handshake.  Note that some TLS messages are
elided from the exchange for the sake of brevity.

The critical messages for this example are the server requesting a certificate
with a TLS CertificateRequest (\*3); this request might use information about
the request or resource.  The client then provides a certificate and proof of
possession of the private key in Certificate and CertificateVerify messages (\*4).

When the handshake completes, the server performs any authorization checks a
second time.  With the client certificate available, it then authorizes the
request and provides a response (\*5).

### Using TLS 1.3

TLS 1.3 [I-D.ietf-tls-tls13] introduces a new client authentication mechanism
that allows for clients to authenticate after the handshake has been completed.
For the purposes of authenticating an HTTP request, this is functionally
equivalent to renegotiation.  {{ex-tls13}} shows the simpler exchange this
enables.

~~~
Client                                      Server
   -- (HTTP) GET /protected ------------------->
   <---------------- (TLS) CertificateRequest --
   -- (TLS) Certificate ----------------------->
   <--------------------------- (HTTP) 200 OK --
~~~
{: #ex-tls13 title="HTTP/1.1 Reactive Certificate Authentication with TLS 1.3"}

TLS 1.3 does not support renegotiation, instead supporting direct client
authentication.  In contrast to the TLS 1.2 example, in TLS 1.3, a server can
simply request a certificate.

## Reactive Client Authentication in HTTP/2

An important part of the HTTP/1.1 exchange is that the client is able to easily
identify the request that caused the TLS renegotiation.  The client is able to
assume that the next unanswered request on the connection is responsible.  The
HTTP stack in the client is then able to direct the certificate request to the
application or component that initiated that request.  This ensures that the
application has the right contextual information for processing the request.

In HTTP/2, a client can have multiple outstanding requests.  Without some sort
of correlation information, a client is unable to identify which request caused
the server to request a certificate.

Thus, the minimum necessary mechanism to support reactive certificate
authentication in HTTP/2 is an identifier that can be use to correlate an HTTP
request with either a TLS renegotiation or CertificateRequest.

Such an identifier could be added to TLS 1.2 by means of an extension, but
many TLS 1.2 implementations do not permit application data to continue
during a renegotiation.  This is problematic for a multiplexed protocol like
HTTP/2.  Instead, this draft proposes bringing the TLS 1.3 CertificateRequest
and Certificate messages into HTTP/2 frames, making client certificate
authentication TLS-version-agnostic.

~~~
Client                                      Server
   -- (streams 1,3,5) GET /protected ---------->
   <---- (streams 1,3,5) CERTIFICATE_REQUIRED --
   <---------- (stream 0) CERTIFICATE_REQUEST --
   -- (stream 0) CERTIFICATE ------------------>
   -- (stream 0) CERTIFICATE_PROOF ------------>
   ------ (stream 1,3,5) USE_CERTIFICATE* ----->
   <------------------ (streams 1,3,5) 200 OK --
   
* - Optional
~~~
{: #ex-http2 title="HTTP/2 Reactive Certificate Authentication"}

{{certs-http2}} describes how certificates can be requested and presented
at the HTTP/2 framing layer using several new frame types which parallel
the TLS 1.3 message exchange.  {{errors}} defines new error types which
can be used to notify peers when the exchange has not been successful.
Finally, {{setting}} describes how an HTTP/2 client can announce
support for this feature so that a server might use these capabilities.

## Terminology

RFC 2119 [RFC2119] defines the terms "MUST", "MUST NOT", "SHOULD" and "MAY".


# Presenting Client Certificates at the HTTP/2 Framing Layer {#certs-http2}

An HTTP/2 request from a client that has signaled support for reactive
certificate authentication (see {{setting}}) might cause a server to request
client authentication.  In HTTP/2 a server does this by sending at least one
`CERTIFICATE_REQUEST` frame (see {{http-cert-request}}) on stream zero.

The server SHOULD first send a `CERTIFICATE_REQUIRED` frame (see 
{{http-cert-required}}) on the stream which triggered the request for 
client credentials. The Request-ID field of the `CERTIFICATE_REQUEST` 
frame is populated by the server with the same value in the 
`CERTIFICATE_REQUIRED` frame. Subsequent `CERTIFICATE_REQUIRED` frames 
with the same request identifier MAY be sent on other streams where the 
server is expecting client authentication with the same parameters. This 
allows a client to correlate the `CERTIFICATE_REQUEST` with one or more 
outstanding HTTP requests. 

A server MAY send multiple concurrent `CERTIFICATE_REQUEST` frames. If a 
server requires that a client provide multiple certificates before 
authorizing a single request, it MUST send a `CERTIFICATE_REQUIRED` 
frame with a different request identifier and a corresponding 
`CERTIFICATE_REQUEST` frame for each required certificate. 

Clients provide certificate authentication by sending a `CERTIFICATE` frame (see
{{http-certificate}}) on stream zero.  If the `CERTIFICATE` frame is marked as
both `SOLICITED` and `AUTOMATIC_USE`, the provided certificate can be immediately
applied by the server to all streams on which a `CERTIFICATE_REQUIRED` frame has
been sent previously with the same identifier.  Otherwise, the client will send
subsequent `USE_CERTIFICATE` frames (see {{http-use-certificate}}) to indicate
the streams on which it intends the certificate to be considered.

Clients may also provide authentication without being asked, if desired, by sending
`CERTIFICATE` and `USE_CERTIFICATE` frames without waiting for a server-generated
`CERTIFICATE_REQUEST`.  If a client receives a `CERTIFICATE_REQUIRED` frame referencing
parameters for which it has already provided a matching certificate, it MAY reply with
a `USE_CERTIFICATE` frame referencing the previous `CERTIFICATE` frame.

## The CERTIFICATE_REQUEST Frame {#http-cert-request}

TLS 1.3 defines the `CertificateRequest` message, which prompts the client to
provide a certificate which conforms to certain properties specified by the
server.  This draft defines the `CERTIFICATE_REQUEST` frame (0xFRAME-TBD1), which
contains the same contents as a TLS 1.3 `CertificateRequest` message, but can
be sent over any TLS version.

The `CERTIFICATE_REQUEST` frame MUST NOT be sent by clients.  A `CERTIFICATE_REQUEST`
frame received by a server SHOULD be rejected with a stream error of type
`PROTOCOL_ERROR`.

The `CERTIFICATE_REQUEST` frame MUST be sent on stream zero.  A `CERTIFICATE_REQUEST`
frame received on any other stream MUST be rejected with a stream error of type
`PROTOCOL_ERROR`.

~~~~~~~~~~~~~~~
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-------------------------------+-------------------------------+
 | ID-Length (8) |               Request-ID                    ...
 +-------------------------------+-------------------------------+
 |     Algorithm-Count (16)      |          Algorithms         ...
 +---------------------------------------------------------------+
 |       CA-Count (16)           |  Certificate-Authorities(?) ...
 +---------------------------------------------------------------+
 | Cert-Extension-Count (16)     |       Cert-Extensions(?)    ...
 +---------------------------------------------------------------+
~~~~~~~~~~~~~~~
{: #fig-cert-request title="CERTIFICATE_REQUEST frame payload"}

The frame contains the following fields:

ID-Length and Request-ID:
: `Request-ID` is a variable-length opaque identifier used to correlate
subsequent certificate-related frames with this request.  The identifier
MUST be the output of a cryptographically-secure pseudo-random function.
The size of the `Request-ID` field is given by the 8-bit `ID-Length` field,
which MUST NOT be zero.
    
Algorithm-Count and Algorithms:
: A list of the hash/signature algorithm pairs that the server is able 
to verify, listed in descending order of preference. Any certificates 
provided by the client MUST be signed using a hash/signature algorithm 
pair found in `Algorithms`. Each algorithm pair is encoded as a 
`SignatureAndHashAlgorithm` (see [I-D.ietf-tls-tls13] section 6.3.2.1), 
and the number of such structures is given by the 16-bit 
`Algorithm-Count` field, which MUST NOT be zero. 

CA-Count and Certificate-Authorities:
: `Certificate-Authorities` is a series of distinguished names of
acceptable certificate authorities, represented in DER-encoded [X690] format.
These distinguished names may specify a desired distinguished name for a root
CA or for a subordinate CA; thus, this message can be used to describe known
roots as well as a desired authorization space. The number of such structures
is given by the 16-bit `CA-Count` field, which MAY be zero. If the `CA-Count`
field is zero, then the client MAY send any certificate that meets the rest
of the selection criteria in the `CERTIFICATE_REQUEST`, unless there is some
external arrangement to the contrary. 
    
Cert-Extension-Count and Cert-Extensions:
: A list of certificate extension OIDs [RFC5280] with their allowed 
values, represented in a series of `CertificateExtension` structures 
(see [I-D.ietf-tls-tls13] section 6.3.5). The list of OIDs MUST be used 
in certificate selection as described in {{I-D.ietf-tls-tls13}}. The 
number of Cert-Extension structures is given by the 16-bit 
`Cert-Extension-Count` field, which MAY be zero. 

Some certificate extension OIDs allow multiple values (e.g. Extended Key 
Usage). If the sender has included a non-empty certificate_extensions 
list, the certificate MUST contain all of the specified extension OIDs 
that the recipient recognizes. For each extension OID recognized by the 
recipient, all of the specified values MUST be present in the 
certificate (but the certificate MAY have other values as well). 
However, the recipient MUST ignore and skip any unrecognized certificate 
extension OIDs. 

PKIX RFCs define a variety of certificate extension OIDs and their 
corresponding value types. Depending on the type, matching certificate 
extension values are not necessarily bitwise-equal. It is expected that 
implementations will rely on their PKI libraries to perform certificate 
selection using these certificate extension OIDs. 

## The CERTIFICATE_REQUIRED frame {#http-cert-required}

The `CERTIFICATE_REQUIRED` frame (0xFRAME-TBD2) is sent by servers to indicate that
processing of a request is blocked pending certificate authentication. The frame
includes a request identifier which can be used to correlate the stream with
a `CERTIFICATE_REQUEST` frame received on stream zero.

The `CERTIFICATE_REQUIRED` frame contains between 1 and 255 octets, which is the
authentication request identifier.  A client that receives a `CERTIFICATE_REQUIRED` of
any other length MUST treat this as a stream error of type `PROTOCOL_ERROR`.
Frames with identical request identifiers refer to the same `CERTIFICATE_REQUEST`.

The `CERTIFICATE_REQUIRED` frame MUST NOT be sent by clients.  A `CERTIFICATE_REQUIRED`
frame received by a server SHOULD be rejected with a stream error of type
PROTOCOL_ERROR.

The server MUST NOT send a `CERTIFICATE_REQUIRED` frame on stream zero, a
server-initiated stream or a stream that does not have an outstanding request.
In other words, a server can only send in the "open" or "half-closed (remote)"
stream states.

A client that receives a `CERTIFICATE_REQUIRED` frame on a stream which is not in a
valid state ("open" or "half-closed (local)" for clients) SHOULD treat this as a
connection error of type `PROTOCOL_ERROR`.

## The CERTIFICATE frame {#http-certificate}

The `CERTIFICATE` frame (0xFRAME-TBD3) allows the sender to provide elements of a
certificate chain which can be used as authentication for previous or subsequent
requests.

The `CERTIFICATE` frame defines one flag:

SOLICITED (0x01): : If set, indicates that the `CERTIFICATE` (and 
possibly `CERTIFICATE_PROOF`) frame(s) are being sent in response to a 
`CERTIFICATE_REQUEST` frame. 
 
The payload of a `CERTIFICATE` frame contains elements of a certificate 
chain, terminating in an end certificate. Multiple `CERTIFICATE` frames 
MAY be sent with the same Certificate-ID, to accomodate certificate 
chains which are too large to fit in a single HTTP/2 frame (see 
[RFC7540] section 4.2). The flag values MUST be identical for each 
`CERTIFICATE` frame sent with the same Certificate-ID. 

Particularly when a certificate contains a large number of Subject
Alternative Names, it might not fit into a single `CERTIFICATE` frame
even as the only provided certificate.  Senders unable to transfer a
requested certificate due to the recipient's `SETTINGS_MAX_FRAME_SIZE`
value SHOULD increase their own `SETTINGS_MAX_FRAME_SIZE` to a size
that would accomodate their certificate, then terminate affected
streams with `CERTIFICATE_TOO_LARGE`.

Use of the `CERTIFICATE` frame by servers is not defined by this 
document. A `CERTIFICATE` frame received by a client MUST be ignored. 

The `CERTIFICATE` frame MUST be sent on stream zero.  A `CERTIFICATE` frame received
on any other stream MUST be rejected with a stream error of type `PROTOCOL_ERROR`.

~~~~~~~~~~~~
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-------------------------------+-------------------------------+
 | ID-Length (8) |              Certificate-ID (*)             ...
 +-------------------------------+-------------------------------+
 | Cert-Count(8) |             Certificate-List (*)            ...
 +---------------------------------------------------------------+
 
~~~~~~~~~~~~~~~
{: #fig-cert-frame title="CERTIFICATE frame payload"}

The fields defined by the `CERTIFICATE` frame are:

ID-Length and Certificate-ID:
:   If the `CERTIFICATE` frame is in response to
    a `CERTIFICATE_REQUEST` from the server, the ID of that request.  Otherwise,
    a client-selected identifier for this certificate.  The identifier MUST be
    the output of a cryptographically-secure pseudo-random function.

Cert-Count and Certificate-List:
:   A sequence of Certificate objects (see {{cert-cert}}), each 
    representing one certificate in the sender's certificate chain. For the 
    first or only `CERTIFICATE` frame with a given Certificate-ID, the 
    sender's certificate MUST be the first in the list. Each subsequent 
    certificate SHOULD directly certify the certificate immediately 
    preceding it. A certificate which specifies a trust anchor MAY be 
    omitted, provided that the recipient is known to already possess the 
    relevant certificate. (For example, because it was included in a 
    `CERTIFICATE_REQUEST`'s Certificate-Authorities list.) `Cert-Count` 
    describes the number of certificates provided.

A `CERTIFICATE` frame with a `Cert-Count` of zero indicates a refusal of 
a `CERTIFICATE_REQUEST` -- the sender either does not have or does not 
wish to provide a matching certificate. Servers SHOULD process all 
corresponding requests as unauthenticated, likely returning an 
authentication-related error at the HTTP level (e.g. 403).

If the `CERTIFICATE` frame is sent without being requested, the 
`SOLICITED` flag MUST NOT be set. When the `CERTIFICATE` frame is sent 
in response to a `CERTIFICATE_REQUEST` frame, the `SOLICITED` flag MUST 
be set, and the `Request-ID` field MUST contain the same value as the 
corresponding `CERTIFICATE_REQUEST` frame. In this case, the provided 
certificate chain MUST conform to the requirements expressed in the 
`CERTIFICATE_REQUEST` to the best of the client's ability. Specifically: 

  - If the `CERTIFICATE_REQUEST` contained a non-empty `Certificate-Authorities`
    element, one of the certificates in the chain SHOULD be signed by one of the
    listed CAs.
    
  - If the `CERTIFICATE_REQUEST` contained a non-empty `Cert-Extensions` element,
    the first certificate MUST match with regard to the extension OIDs recognized
    by the client.
    
  - Each certificate that is not self-signed MUST be signed using a hash/signature
    algorithm listed in the `Algorithms` element.

If these requirements are not satisfied, the server MAY at its discretion either
process the request without client authentication, or respond with a stream error
{{RFC7540}} on any stream where the certificate is used.  {{errors}} defines
certificate-related error codes which might be applicable.

### The Certificate structure {#cert-cert}

~~~~~~~~~~~~~~~
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-------------------------------+-------------------------------+
 |                    Cert-Length (24)           |    Cert (*) ...
 +---------------------------------------------------------------+
~~~~~~~~~~~~~~~
{: #fig-cert-cert title="Certificate structure"}

The Certificate structure is a length-prefixed X.509v3 [RFC5280]
certificate.  The certificate MUST be signed with an acceptable
hash/signature algorithm pair, if the recipient's list of acceptable
pairs is known.

## The CERTIFICATE_PROOF Frame {#cert-proof}

The `CERTIFICATE_PROOF` frame proves possession of the private key corresponding
to an end certificate previously shown in a `CERTIFICATE` frame, along with
its certificate chain in the same or other `CERTIFICATE` frames.

The `CERTIFICATE_PROOF` frame defines two flags:

SOLICITED (0x01):
: If set, indicates that the `CERTIFICATE` and `CERTIFICATE_PROOF` 
frames are being sent in response to a `CERTIFICATE_REQUEST` frame. 
 
AUTOMATIC_USE (0x02):
: If set, the recipient SHOULD consider the certificate when authenticating 
future requests. Otherwise, the certificate MUST only be considered for 
requests on streams where a `USE_CERTIFICATE` frame (see 
{{http-use-certificate}}) has been sent. 

~~~~~~~~~~~~
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-------------------------------+-------------------------------+
 | ID-Length (8) |              Certificate-ID (*)             ...
 +-------------------------------+-------------------------------+
 |         Algorithm (16)        |         Sig-Length (16)       |
 +---------------------------------------------------------------+
 |                         Signature (*)                       ...
 +---------------------------------------------------------------+
 
~~~~~~~~~~~~~~~
{: #fig-proof-frame title="CERTIFICATE_PROOF frame payload"}

The `CERTIFICATE_PROOF` frame (0xFRAME-TBD4) contains an `Algorithm` field (a 
`SignatureAndHashAlgorithm`, from [I-D.ietf-tls-tls13] section 6.3.2.1), 
describing the hash/signature algorithm pair being used. The signature 
is performed as described in [I-D.ietf-tls-tls13], with the following 
values being used: 

  - The context string for the signature is "HTTP/2 CERTIFICATE"
  - The "specified content" is an [RFC5705] exported value, with the following parameters:
    - Disambiguating label string: "EXPORTER HTTP/2 CERTIFICATE"
    - Context: The Certificate-ID chosen by the application
    - Length:  1024 bytes

Because the exported value can be independently calculated by both sides of the
TLS connection, the value to be signed is not sent on the wire at any time.

A `CERTIFICATE_PROOF` frame MUST be sent only after all `CERTIFICATE` 
frames with the same Certificate-ID have been sent, and MUST correspond 
to the first certificate presented in the first `CERTIFICATE` frame with 
that Certificate-ID. Receipt of multiple `CERTIFICATE_PROOF` frames for 
the same Certificate-ID, receipt of a `CERTIFICATE_PROOF` frame 
without a corresponding `CERTIFICATE` frame, or receipt of a `CERTIFICATE`
frame after a corresponding `CERTIFICATE_PROOF` MUST be treated as a session 
error of type `PROTOCOL_ERROR`. 

Use of the `CERTIFICATE_PROOF` frame by servers is not defined by this 
document. A `CERTIFICATE_PROOF` frame received by a client MUST be ignored. 

## The USE_CERTIFICATE Frame {#http-use-certificate}

The `USE_CERTIFICATE` frame (0xFRAME-TBD5) is sent by clients to 
indicate that processing of a request should use a certificate provided 
in a previous `CERTIFICATE` frame and proved by a preceding 
`CERTIFICATE_PROOF` frame. The frame includes a certificate identifier 
which can be used to correlate the stream with a `CERTIFICATE` frame 
received on stream zero. 

A `USE_CERTIFICATE` frame with no payload expresses the client's choice to proceed
without providing a certificate.  Servers SHOULD process the request as unauthenticated,
likely returning an authentication-related error at the HTTP level (e.g. 403).

Otherwise, the `USE_CERTIFICATE` frame contains between 1 and 255 octets, which is
the authentication request identifier.  A server that receives a `USE_CERTIFICATE`
of any other length MUST treat this as a stream error of type `PROTOCOL_ERROR`.
Frames with identical request identifiers refer to the same `CERTIFICATE`.

Use of the `USE_CERTIFICATE` frame by servers is not defined by this 
document. A `USE_CERTIFICATE` frame received by a client MUST be 
ignored. 

The client MUST NOT send a `USE_CERTIFICATE` frame on stream zero, a
server-initiated stream or a stream that does not have an outstanding request.
In other words, a client can only send in the "open" or "half-closed (local)"
stream states.

A server that receives a `USE_CERTIFICATE` frame on a stream which is not in a
valid state ("open" or "half-closed (remote)" for servers) SHOULD treat this as a
connection error of type `PROTOCOL_ERROR`.

# Indicating failures during HTTP-Layer Certificate Authentication {#errors} 

Because this draft permits client certificates to be exchanged at the 
HTTP framing layer instead of the TLS layer, several certificate-related 
errors which are defined at the TLS layer might now occur at the HTTP 
framing layer. In this section, those errors are restated and added to 
the HTTP/2 error code registry. 

BAD_CERTIFICATE (0xERROR-TBD1):
:  A certificate was corrupt, contained signatures
   that did not verify correctly, etc.
   
UNSUPPORTED_CERTIFICATE (0xERROR-TBD2):
:  A certificate was of an unsupported type

CERTIFICATE_REVOKED (0xERROR-TBD3):
:  A certificate was revoked by its signer

CERTIFICATE_EXPIRED (0xERROR-TBD4):
:  A certificate has expired or is not currently valid

BAD_SIGNATURE (0xERROR-TBD5):
:  The digital signature provided did not match

CERTIFICATE_TOO_LARGE (0xERROR-TBD6):
:  The certificate cannot be transferred due to the recipient's 
`SETTINGS_MAX_FRAME_SIZE` 

CERTIFICATE_GENERAL (0xERROR-TBD7):
:  Any other certificate-related error

As described in [RFC7540], implementations MAY choose to treat a stream error as
a connection error at any time.  Of particular note, a stream error cannot occur
on stream 0, which means that implementations cannot send non-session errors in
response to `CERTIFICATE_REQUEST` and `CERTIFICATE` frames.  Implementations which do
not wish to terminate the connection MAY either send relevant errors on any stream
which references the failing certificate in question or process the requests as
unauthenticated and provide error information at the HTTP semantic layer.

# Indicating Support for HTTP-Layer Certificate Authentication {#setting}

Clients that support HTTP-layer certificate authentication indicate
this using the HTTP/2 `SETTINGS_HTTP_CERT_AUTH` (0xSETTING-TBD) setting.

The initial value for the `SETTINGS_HTTP_CERT_AUTH` setting is 0, indicating that
the client does not support reactive certificate authentication.  A client sets the
`SETTINGS_HTTP_CERT_AUTH` setting to a value of 1 to indicate support for
HTTP-layer certificate authentication as defined in this document.  Any value
other than 0 or 1 MUST be treated as a connection error (Section 5.4.1 of
[RFC7540]) of type `PROTOCOL_ERROR`.

# Security Considerations {#security}

Implementations need to be aware of the potential for confusion about the state
of a connection.  Because a client's unsolicited certificate might race with
the server's request for a certificate, failure to answer a `CERTIFICATE_REQUEST`
is not necessarily an attack.  At the same time, failure to provide a certificate
on a stream after receiving `CERTIFICATE_REQUIRED` blocks server processing, and
SHOULD be subject to standard timeouts used to guard against unresponsive peers.

The presence or absence of a validated client certificate can change during the
processing of a request, potentially multiple times.  A server that uses
reactive certificate authentication needs to be prepared to reevaluate the
authorization state of a request as the set of certificates changes.  This might
occur without frames on-stream, if a `CERTIFICATE` frame with the `AUTOMATIC_USE`
flag is received.

# IANA Considerations {#iana}

The HTTP/2 `SETTINGS_HTTP_CERT_AUTH` setting is registered in {{iana-setting}}.
Four frame types are registered in {{iana-frame}}.  Five error codes are registered
in {{iana-errors}}.

## HTTP/2 SETTINGS_HTTP_CERT_AUTH Setting {#iana-setting}

The SETTINGS_HTTP_CERT_AUTH setting is registered in the "HTTP/2 Settings"
registry established in [RFC7540].

Name:
: SETTINGS_HTTP_CERT_AUTH

Code:
: 0xSETTING-TBD

Initial Value:
: 0

Specification:
: This document.

## New HTTP/2 Frames {#iana-frame}

Four new frame types are registered in the "HTTP/2 Frame Types"
registry established in [RFC7540].

### CERTIFICATE_REQUIRED

Frame Type:
: CERTIFICATE_REQUIRED

Code:
: 0xFRAME-TBD1

Specification:
: This document.

### CERTIFICATE_REQUEST

Frame Type:
: CERTIFICATE_REQUEST

Code:
: 0xFRAME-TBD2

Specification:
: This document.

### CERTIFICATE

Frame Type:
: CERTIFICATE

Code:
: 0xFRAME-TBD3

Specification:
: This document.

### CERTIFICATE_PROOF

Frame Type:
: CERTIFICATE_PROOF

Code:
: 0xFRAME-TBD4

Specification:
: This document.

### USE_CERTIFICATE

Frame Type:
: USE_CERTIFICATE

Code:
: 0xFRAME-TBD5

Specification:
: This document.

## New HTTP/2 Error Codes {#iana-errors}

Five new error codes are registered in the "HTTP/2 Error Code"
registry established in [RFC7540].

### BAD_CERTIFICATE

Name:
: BAD_CERTIFICATE

Code:
: 0xERROR-TBD1

Specification:
: This document.


### UNSUPPORTED_CERTIFICATE

Name:
: UNSUPPORTED_CERTIFICATE

Code:
: 0xERROR-TBD2

Specification:
: This document.

### CERTIFICATE_REVOKED

Name:
: CERTIFICATE_REVOKED

Code:
: 0xERROR-TBD3

Specification:
: This document.

### CERTIFICATE_EXPIRED

Name:
: CERTIFICATE_EXPIRED

Code:
: 0xERROR-TBD4

Specification:
: This document.

### BAD_SIGNATURE

Name:
: BAD_SIGNATURE

Code:
: 0xERROR-TBD5

Specification:
: This document.


### CERTIFICATE_GENERAL

Name:
: CERTIFICATE_GENERAL

Code:
: 0xERROR-TBD6

Specification:
: This document.

# Acknowledgements {#ack}

Eric Rescorla pointed out several failings in an earlier revision.
Andrei Popov contributed to the TLS considerations.


--- back
