-- |
-- Module      : Network.TLS.Parameters
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Parameters
    (
      ClientParams(..)
    , ServerParams(..)
    , CommonParams
    , ClientHooks(..)
    , ServerHooks(..)
    , Supported(..)
    , Shared(..)
    -- * special default
    , defaultParamsClient
    -- * Parameters
    , MaxFragmentEnum(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    ) where

import Network.BSD (HostName)

import Network.TLS.Extension
import Network.TLS.Struct
import qualified Network.TLS.Struct as Struct
import Network.TLS.Session
import Network.TLS.Cipher
import Network.TLS.Measurement
import Network.TLS.Compression
import Network.TLS.Crypto
import Network.TLS.Credentials
import Network.TLS.X509
import Data.Monoid
import Data.Default.Class
import qualified Data.ByteString as B

import Control.Monad.IO.Class

type CommonParams m = (Supported, Shared m)

data ClientParams m = ClientParams
    { clientUseMaxFragmentLength    :: Maybe MaxFragmentEnum
      -- | Define the name of the server, along with an extra service identification blob.
      -- this is important that the hostname part is properly filled for security reason,
      -- as it allow to properly associate the remote side with the given certificate
      -- during a handshake.
      --
      -- The extra blob is useful to differentiate services running on the same host, but that
      -- might have different certificates given. It's only used as part of the X509 validation
      -- infrastructure.
    , clientServerIdentification      :: (HostName, Bytes)
      -- | Allow the use of the Server Name Indication TLS extension during handshake, which allow
      -- the client to specify which host name, it's trying to access. This is useful to distinguish
      -- CNAME aliasing (e.g. web virtual host).
    , clientUseServerNameIndication   :: Bool
      -- | try to establish a connection using this session.
    , clientWantSessionResume         :: Maybe (SessionID, SessionData)
    , clientShared                    :: Shared m
    , clientHooks                     :: ClientHooks m
    , clientSupported                 :: Supported
    } deriving (Show)

defaultParamsClient :: MonadIO m => HostName -> Bytes -> ClientParams m
defaultParamsClient serverName serverId = ClientParams
    { clientWantSessionResume    = Nothing
    , clientUseMaxFragmentLength = Nothing
    , clientServerIdentification = (serverName, serverId)
    , clientUseServerNameIndication = True
    , clientShared               = def
    , clientHooks                = def
    , clientSupported            = def
    }

data ServerParams m = ServerParams
    { -- | request a certificate from client.
      serverWantClientCert    :: Bool

      -- | This is a list of certificates from which the
      -- disinguished names are sent in certificate request
      -- messages.  For TLS1.0, it should not be empty.
    , serverCACertificates :: [SignedCertificate]

      -- | Server Optional Diffie Hellman parameters. If this value is not
      -- properly set, no Diffie Hellman key exchange will take place.
    , serverDHEParams         :: Maybe DHParams

    , serverShared            :: Shared m
    , serverHooks             :: ServerHooks m
    , serverSupported         :: Supported
    } deriving (Show)

defaultParamsServer :: MonadIO m => ServerParams m
defaultParamsServer = ServerParams
    { serverWantClientCert   = False
    , serverCACertificates   = []
    , serverDHEParams        = Nothing
    , serverHooks            = def
    , serverShared           = def
    , serverSupported        = def
    }

instance MonadIO m => Default (ServerParams m) where
    def = defaultParamsServer

-- | List all the supported algorithms, versions, ciphers, etc supported.
data Supported = Supported
    {
      -- | Supported Versions by this context
      -- On the client side, the highest version will be used to establish the connection.
      -- On the server side, the highest version that is less or equal than the client version will be chosed.
      supportedVersions       :: [Version]
      -- | Supported cipher methods
    , supportedCiphers        :: [Cipher]
      -- | supported compressions methods
    , supportedCompressions   :: [Compression]
      -- | All supported hash/signature algorithms pair for client
      -- certificate verification, ordered by decreasing priority.
    , supportedHashSignatures :: [HashAndSignatureAlgorithm]
      -- | Set if we support secure renegotiation.
    , supportedSecureRenegotiation :: Bool
      -- | Set if we support session.
    , supportedSession             :: Bool
    } deriving (Show,Eq)

defaultSupported :: Supported
defaultSupported = Supported
    { supportedVersions       = [TLS12,TLS11,TLS10]
    , supportedCiphers        = []
    , supportedCompressions   = [nullCompression]
    , supportedHashSignatures = [ (Struct.HashSHA512, SignatureRSA)
                                , (Struct.HashSHA384, SignatureRSA)
                                , (Struct.HashSHA256, SignatureRSA)
                                , (Struct.HashSHA224, SignatureRSA)
                                , (Struct.HashSHA1,   SignatureRSA)
                                , (Struct.HashSHA1,   SignatureDSS)
                                ]
    , supportedSecureRenegotiation = True
    , supportedSession             = True
    }

instance Default Supported where
    def = defaultSupported

data Shared m = Shared
    { sharedCredentials     :: Credentials
    , sharedSessionManager  :: SessionManager m
    , sharedCAStore         :: CertificateStore
    , sharedValidationCache :: ValidationCache
    }

instance Show (Shared m) where
    show _ = "Shared"
instance Monad m => Default (Shared m) where
    def = Shared
            { sharedCAStore         = mempty
            , sharedCredentials     = mempty
            , sharedSessionManager  = noSessionManager
            , sharedValidationCache = def
            }

-- | A set of callbacks run by the clients for various corners of TLS establishment
data ClientHooks m = ClientHooks
    { -- | This action is called when the server sends a
      -- certificate request.  The parameter is the information
      -- from the request.  The action should select a certificate
      -- chain of one of the given certificate types where the
      -- last certificate in the chain should be signed by one of
      -- the given distinguished names.  Each certificate should
      -- be signed by the following one, except for the last.  At
      -- least the first of the certificates in the chain must
      -- have a corresponding private key, because that is used
      -- for signing the certificate verify message.
      --
      -- Note that is is the responsibility of this action to
      -- select a certificate matching one of the requested
      -- certificate types.  Returning a non-matching one will
      -- lead to handshake failure later.
      --
      -- Returning a certificate chain not matching the
      -- distinguished names may lead to problems or not,
      -- depending whether the server accepts it.
      onCertificateRequest :: ([CertificateType],
                               Maybe [HashAndSignatureAlgorithm],
                               [DistinguishedName]) -> m (Maybe (CertificateChain, PrivKey))
    , onNPNServerSuggest   :: Maybe ([B.ByteString] -> m B.ByteString)
    , onServerCertificate  :: CertificateStore -> ValidationCache -> ServiceID -> CertificateChain -> m [FailedReason]
    , onSuggestALPN :: m (Maybe [B.ByteString])
    }

defaultClientHooks :: MonadIO m => ClientHooks m
defaultClientHooks = ClientHooks
    { onCertificateRequest = \ _ -> return Nothing
    , onNPNServerSuggest   = Nothing
    , onServerCertificate  = \s c i cc -> liftIO $ validateDefault s c i cc
    , onSuggestALPN        = return Nothing
    }

instance Show (ClientHooks m) where
    show _ = "ClientHooks"
instance MonadIO m => Default (ClientHooks m) where
    def = defaultClientHooks

-- | A set of callbacks run by the server for various corners of the TLS establishment
data ServerHooks m = ServerHooks
    {
      -- | This action is called when a client certificate chain
      -- is received from the client.  When it returns a
      -- CertificateUsageReject value, the handshake is aborted.
      onClientCertificate :: CertificateChain -> m CertificateUsage

      -- | This action is called when the client certificate
      -- cannot be verified.  A 'Nothing' argument indicates a
      -- wrong signature, a 'Just e' message signals a crypto
      -- error.
    , onUnverifiedClientCert :: m Bool

      -- | Allow the server to choose the cipher relative to the
      -- the client version and the client list of ciphers.
      --
      -- This could be useful with old clients and as a workaround
      -- to the BEAST (where RC4 is sometimes prefered with TLS < 1.1)
      --
      -- The client cipher list cannot be empty.
    , onCipherChoosing        :: Version -> [Cipher] -> Cipher

      -- | suggested next protocols accoring to the next protocol negotiation extension.
    , onSuggestNextProtocols  :: m (Maybe [B.ByteString])
      -- | at each new handshake, we call this hook to see if we allow handshake to happens.
    , onNewHandshake          :: Measurement -> m Bool
    , onALPNClientSuggest     :: Maybe ([B.ByteString] -> m B.ByteString)
    }

defaultServerHooks :: MonadIO m => ServerHooks m
defaultServerHooks = ServerHooks
    { onCipherChoosing       = \_ -> head
    , onClientCertificate    = \_ -> return $ CertificateUsageReject $ CertificateRejectOther "no client certificates expected"
    , onUnverifiedClientCert = return False
    , onSuggestNextProtocols = return Nothing
    , onNewHandshake         = \_ -> return True
    , onALPNClientSuggest    = Nothing
    }

instance Show (ServerHooks m) where
    show _ = "ClientHooks"
instance MonadIO m => Default (ServerHooks m) where
    def = defaultServerHooks
