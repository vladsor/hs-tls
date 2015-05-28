{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}

-- |
-- Module      : Network.TLS.Context
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Context
    (
    -- * Context configuration
      TLSParams

    -- * Context object and accessor
    , Context(..)
    , Hooks(..)
    , ctxEOF
    , ctxHasSSLv2ClientHello
    , ctxDisableSSLv2ClientHello
    , ctxEstablished
    , withLog
    , ctxWithHooks
    , contextModifyHooks
    , setEOF
    , setEstablished
    , contextFlush
    , contextClose
    , contextSend
    , contextRecv
    , updateMeasure
    , withMeasure
    , withReadLock
    , withWriteLock
    , withStateLock
    , withRWLock

    -- * information
    , Information(..)
    , contextGetInformation

    -- * New contexts
    , contextNew
    -- * Deprecated new contexts methods
    , contextNewOnHandle
    , contextNewOnSocket

    -- * Context hooks
    , contextHookSetHandshakeRecv
    , contextHookSetCertificateRecv
    , contextHookSetLogging

    -- * Using context states
    , throwCore
    , usingState
    , usingState_
    , runTxState
    , runRxState
    , usingHState
    , getHState
    , getStateRNG
    ) where

import Network.TLS.Backend
import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Cipher (Cipher(..), CipherKeyExchangeType(..))
import Network.TLS.Credentials
import Network.TLS.State
import Network.TLS.Hooks
import Network.TLS.Record.State
import Network.TLS.Parameters
import Network.TLS.Measurement
import Network.TLS.Types (Role(..))
import Network.TLS.Handshake (handshakeClient, handshakeClientWith, handshakeServer, handshakeServerWith)
import Network.TLS.X509
import Data.Maybe (isJust)

import Crypto.Random

import Control.Concurrent.MVar
import Control.Monad.State
import Control.Monad.Catch
import Data.IORef

-- deprecated imports
import Network.Socket (Socket)
import System.IO (Handle)

class TLSParams a m | a -> m where
    getTLSCommonParams :: a -> CommonParams m
    getTLSRole         :: a -> Role
    getCiphers         :: a -> [Cipher]
    doHandshake        :: a -> Context m -> m ()
    doHandshakeWith    :: a -> Context m -> Handshake -> m ()

instance (Functor m, MonadCatch m, MonadIO m) => TLSParams (ClientParams m) m where
    getTLSCommonParams cparams = ( clientSupported cparams
                                 , clientShared cparams
                                 )
    getTLSRole _ = ClientRole
    getCiphers cparams = supportedCiphers $ clientSupported cparams
    doHandshake = handshakeClient
    doHandshakeWith = handshakeClientWith

instance (Functor m, MonadCatch m, MonadIO m) => TLSParams (ServerParams m) m where
    getTLSCommonParams sparams = ( serverSupported sparams
                                 , serverShared sparams
                                 )
    getTLSRole _ = ServerRole
    -- on the server we filter our allowed ciphers here according
    -- to the credentials and DHE parameters loaded
    getCiphers sparams = filter authorizedCKE (supportedCiphers $ serverSupported sparams)
          where authorizedCKE cipher =
                    case cipherKeyExchange cipher of
                        CipherKeyExchange_RSA         -> canEncryptRSA
                        CipherKeyExchange_DH_Anon     -> canDHE
                        CipherKeyExchange_DHE_RSA     -> canSignRSA && canDHE
                        CipherKeyExchange_DHE_DSS     -> canSignDSS && canDHE
                        CipherKeyExchange_ECDHE_RSA   -> canSignRSA
                        -- unimplemented: non ephemeral DH
                        CipherKeyExchange_DH_DSS      -> False
                        CipherKeyExchange_DH_RSA      -> False
                        -- unimplemented: EC
                        CipherKeyExchange_ECDH_ECDSA  -> False
                        CipherKeyExchange_ECDH_RSA    -> False
                        CipherKeyExchange_ECDHE_ECDSA -> False

                canDHE        = isJust $ serverDHEParams sparams
                canSignDSS    = SignatureDSS `elem` signingAlgs
                canSignRSA    = SignatureRSA `elem` signingAlgs
                canEncryptRSA = isJust $ credentialsFindForDecrypting creds
                signingAlgs   = credentialsListSigningAlgorithms creds
                creds         = sharedCredentials $ serverShared sparams
    doHandshake = handshakeServer
    doHandshakeWith = handshakeServerWith

-- | create a new context using the backend and parameters specified.
contextNew :: (MonadIO m, CPRG rng, HasBackend backend m, TLSParams params m)
           => backend   -- ^ Backend abstraction with specific method to interact with the connection type.
           -> params    -- ^ Parameters of the context.
           -> rng       -- ^ Random number generator associated with this context.
           -> m (Context m)
contextNew backend params rng = do
    initializeBackend backend

    let role = getTLSRole params
        st   = newTLSState rng role
        (supported, shared) = getTLSCommonParams params
        ciphers = getCiphers params

    when (null ciphers) $ error "no ciphers available with those parameters"

    stvar <- liftIO $ newMVar st
    eof   <- liftIO $ newIORef False
    established <- liftIO $ newIORef False
    stats <- liftIO $ newIORef newMeasurement
    -- we enable the reception of SSLv2 ClientHello message only in the
    -- server context, where we might be dealing with an old/compat client.
    sslv2Compat <- liftIO $ newIORef (role == ServerRole)
    needEmptyPacket <- liftIO $ newIORef False
    hooks <- liftIO $ newIORef defaultHooks
    tx    <- liftIO $ newMVar newRecordState
    rx    <- liftIO $ newMVar newRecordState
    hs    <- liftIO $ newMVar Nothing
    lockWrite <- liftIO $ newMVar ()
    lockRead  <- liftIO $ newMVar ()
    lockState <- liftIO $ newMVar ()

    return $ Context
            { ctxConnection   = getBackend backend
            , ctxShared       = shared
            , ctxSupported    = supported
            , ctxCiphers      = ciphers
            , ctxState        = stvar
            , ctxTxState      = tx
            , ctxRxState      = rx
            , ctxHandshake    = hs
            , ctxDoHandshake  = doHandshake params
            , ctxDoHandshakeWith  = doHandshakeWith params
            , ctxMeasurement  = stats
            , ctxEOF_         = eof
            , ctxEstablished_ = established
            , ctxSSLv2ClientHello = sslv2Compat
            , ctxNeedEmptyPacket  = needEmptyPacket
            , ctxHooks            = hooks
            , ctxLockWrite        = lockWrite
            , ctxLockRead         = lockRead
            , ctxLockState        = lockState
            }

-- | create a new context on an handle.
contextNewOnHandle :: (MonadIO m, CPRG rng, TLSParams params m)
                   => Handle -- ^ Handle of the connection.
                   -> params -- ^ Parameters of the context.
                   -> rng    -- ^ Random number generator associated with this context.
                   -> m (Context m)
contextNewOnHandle handle params st = contextNew handle params st
{-# DEPRECATED contextNewOnHandle "use contextNew" #-}

-- | create a new context on a socket.
contextNewOnSocket :: (MonadIO m, CPRG rng, TLSParams params m)
                   => Socket -- ^ Socket of the connection.
                   -> params -- ^ Parameters of the context.
                   -> rng    -- ^ Random number generator associated with this context.
                   -> m (Context m)
contextNewOnSocket sock params st = contextNew sock params st
{-# DEPRECATED contextNewOnSocket "use contextNew" #-}

contextHookSetHandshakeRecv :: MonadIO m => Context m -> (Handshake -> m Handshake) -> m ()
contextHookSetHandshakeRecv context f =
    contextModifyHooks context (\hooks -> hooks { hookRecvHandshake = f })

contextHookSetCertificateRecv :: MonadIO m => Context m -> (CertificateChain -> m ()) -> m ()
contextHookSetCertificateRecv context f =
    contextModifyHooks context (\hooks -> hooks { hookRecvCertificates = f })

contextHookSetLogging :: MonadIO m => Context m -> Logging m -> m ()
contextHookSetLogging context loggingCallbacks =
    contextModifyHooks context (\hooks -> hooks { hookLogging = loggingCallbacks })
