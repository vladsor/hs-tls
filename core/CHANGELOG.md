## Version HEAD

- adding ALPN extension
- adding support for AEAD, and particularly AES128-GCM
- Adding support for ECDH
- Do not support SSL3 by default for security reason.
- add EnumSafe8 and 16 for specific sized Enum instance that are safer
- export signatureAndHash parser/encoder
- add a "known" list of extensions
- add SignatureAlgorithms extension
- add Heartbeat extension
- add support for EC curves and point format extensions
- add preliminary SessionTicket extension
- Debug: Add the ability to choose arbitrary cipher in the client hello.

## Version 1.2.13

- Fix compilation with old mtl version

## Version 1.2.12

- Propagate asynchronous exception

## Version 1.2.11

- use hourglass instead of time
- use tasty instead of test-framework
- add travis file
- remove old de-optimisation flag as the bytestring bug is old now and it conflict with cabal check

## Version 1.2.10

- Update x509 dependencies

## Version 1.2.9

- Export TLSParams and HasBackend type names
- Added FlexibleContexts flag required by ghc-7.9
- debug: add support for specifying the timeout length in milliseconds.
- debug: add support for 3DES in simple client

## Version 1.2.8

- add support for 3DES-EDE-CBC-SHA1 (cipher 0xa)

## Version 1.2.7

- repair retrieve certificate validation, and improve fingerprints
- remove groom from dependency
- make RecordM an instance of Applicative
- Fixes the Error_EOF partial pattern match error in exception handling

## Version 1.2.6 (23 Mar 2014)

- Fixed socket backend endless loop when the server does not close connection
  properly at the TLS level with the close notify alert.
- Catch Error_EOF in recvData and return empty data.

## Version 1.2.5 (23 Mar 2014)

- Fixed Server key exchange data being parsed without the correct
  context, leading to not knowing how to parse the structure.
  The bug happens on efficient server that happens to send the ServerKeyXchg
  message together with the ServerHello in the same handshake packet.
  This trigger parsing of all the messages without having set the pending cipher.
  Delay parsing, when this happen, until we know what to do with it.

## Version 1.2.4 (23 Mar 2014)

- Fixed unrecognized name non-fatal alert after client hello.
- Add SSL3 to the supported list of version by default.
- Fix cereal lower bound to 0.4.0 minimum

## Version 1.2.3 (22 Mar 2014)

- Fixed handshake records not being able to span multiples records.
