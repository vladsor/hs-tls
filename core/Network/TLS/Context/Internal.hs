-- |
-- Module      : Network.TLS.Context.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Context.Internal
    (
    -- * Context configuration
      ClientParams(..)
    , ServerParams(..)
    , defaultParamsClient
    , SessionID
    , SessionData(..)
    , MaxFragmentEnum(..)
    , Measurement(..)

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
import Network.TLS.Extension
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.Compression (Compression)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Hooks
import Network.TLS.Record.State
import Network.TLS.Parameters
import Network.TLS.Measurement
import qualified Data.ByteString as B

import Control.Concurrent.MVar
import Control.Monad.State
import Control.Exception (Exception())
import Data.IORef
import Data.Tuple
import Control.Monad.Catch

-- | Information related to a running context, e.g. current cipher
data Information = Information
    { infoVersion     :: Version
    , infoCipher      :: Cipher
    , infoCompression :: Compression
    } deriving (Show,Eq)

-- | A TLS Context keep tls specific state, parameters and backend information.
data Context m = Context
    { ctxConnection       :: Backend m   -- ^ return the backend object associated with this context
    , ctxSupported        :: Supported
    , ctxShared           :: Shared m
    , ctxCiphers          :: [Cipher]  -- ^ prepared list of allowed ciphers according to parameters
    , ctxState            :: MVar TLSState
    , ctxMeasurement      :: IORef Measurement
    , ctxEOF_             :: IORef Bool    -- ^ has the handle EOFed or not.
    , ctxEstablished_     :: IORef Bool    -- ^ has the handshake been done and been successful.
    , ctxNeedEmptyPacket  :: IORef Bool    -- ^ empty packet workaround for CBC guessability.
    , ctxSSLv2ClientHello :: IORef Bool    -- ^ enable the reception of compatibility SSLv2 client hello.
                                           -- the flag will be set to false regardless of its initial value
                                           -- after the first packet received.
    , ctxTxState          :: MVar RecordState -- ^ current tx state
    , ctxRxState          :: MVar RecordState -- ^ current rx state
    , ctxHandshake        :: MVar (Maybe HandshakeState) -- ^ optional handshake state
    , ctxDoHandshake      :: Context m -> m ()
    , ctxDoHandshakeWith  :: Context m -> Handshake -> m ()
    , ctxHooks            :: IORef (Hooks m)   -- ^ hooks for this context
    , ctxLockWrite        :: MVar ()       -- ^ lock to use for writing data (including updating the state)
    , ctxLockRead         :: MVar ()       -- ^ lock to use for reading data (including updating the state)
    , ctxLockState        :: MVar ()       -- ^ lock used during read/write when receiving and sending packet.
                                           -- it is usually nested in a write or read lock.
    }

updateMeasure :: MonadIO m => Context m -> (Measurement -> Measurement) -> m ()
updateMeasure ctx f = do
    x <- liftIO $ readIORef (ctxMeasurement ctx)
    liftIO $ writeIORef (ctxMeasurement ctx) $! f x

withMeasure :: MonadIO m => Context m -> (Measurement -> m a) -> m a
withMeasure ctx f = liftIO (readIORef (ctxMeasurement ctx)) >>= f

contextFlush :: MonadIO m => Context m -> m ()
contextFlush = backendFlush . ctxConnection

contextClose :: MonadIO m => Context m -> m ()
contextClose = backendClose . ctxConnection

-- | Information about the current context
contextGetInformation :: (MonadThrow m, MonadIO m) => Context m -> m (Maybe Information)
contextGetInformation ctx = do
    ver    <- usingState_ ctx $ gets stVersion
    (cipher,comp) <- failOnEitherError $ runRxState ctx $ gets $ \st -> (stCipher st, stCompression st)
    case (ver, cipher) of
        (Just v, Just c) -> return $ Just $ Information v c comp
        _                -> return Nothing

contextSend :: MonadIO m => Context m -> Bytes -> m ()
contextSend c b = updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxConnection c) b

contextRecv :: MonadIO m => Context m -> Int -> m Bytes
contextRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxConnection c) sz

ctxEOF :: MonadIO m => Context m -> m Bool
ctxEOF ctx = liftIO $ readIORef $ ctxEOF_ ctx

ctxHasSSLv2ClientHello :: MonadIO m => Context m -> m Bool
ctxHasSSLv2ClientHello ctx = liftIO $ readIORef $ ctxSSLv2ClientHello ctx

ctxDisableSSLv2ClientHello :: MonadIO m => Context m -> m ()
ctxDisableSSLv2ClientHello ctx = liftIO $ writeIORef (ctxSSLv2ClientHello ctx) False

setEOF :: MonadIO m => Context m -> m ()
setEOF ctx = liftIO $ writeIORef (ctxEOF_ ctx) True

ctxEstablished :: MonadIO m => Context m -> m Bool
ctxEstablished ctx = liftIO $ readIORef $ ctxEstablished_ ctx

ctxWithHooks :: MonadIO m => Context m -> (Hooks m -> m a) -> m a
ctxWithHooks ctx f = liftIO (readIORef (ctxHooks ctx)) >>= f

contextModifyHooks :: MonadIO m => Context m -> (Hooks m -> Hooks m) -> m ()
contextModifyHooks ctx f = liftIO $ modifyIORef (ctxHooks ctx) f

setEstablished :: MonadIO m => Context m -> Bool -> m ()
setEstablished ctx v = liftIO $ writeIORef (ctxEstablished_ ctx) v

withLog :: MonadIO m => Context m -> (Logging m -> m ()) -> m ()
withLog ctx f = ctxWithHooks ctx (f . hookLogging)

throwCore :: (MonadThrow m, Exception e) => e -> m a
throwCore = throwM

failOnEitherError :: MonadThrow m => m (Either TLSError a) -> m a
failOnEitherError f = do
    ret <- f
    case ret of
        Left err -> throwCore err
        Right r  -> return r

usingState :: MonadIO m => Context m -> TLSSt a -> m (Either TLSError a)
usingState ctx f =
    liftIO $ modifyMVar (ctxState ctx) $ \st ->
            let (a, newst) = runTLSState f st
             in newst `seq` return (newst, a)

usingState_ :: (MonadThrow m, MonadIO m) => Context m -> TLSSt a -> m a
usingState_ ctx f = failOnEitherError $ usingState ctx f

usingHState :: MonadIO m => Context m -> HandshakeM a -> m a
usingHState ctx f = liftIO $ modifyMVar (ctxHandshake ctx) $ \mst ->
    case mst of
        Nothing -> throwCore $ Error_Misc "missing handshake"
        Just st -> return $ swap (Just `fmap` runHandshake st f)

getHState :: MonadIO m => Context m -> m (Maybe HandshakeState)
getHState ctx = liftIO $ readMVar (ctxHandshake ctx)

runTxState :: (MonadThrow m, MonadIO m) => Context m -> RecordM a -> m (Either TLSError a)
runTxState ctx f = do
    ver <- usingState_ ctx (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    liftIO $ modifyMVar (ctxTxState ctx) $ \st ->
        case runRecordM f ver st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

runRxState :: (MonadThrow m, MonadIO m) => Context m -> RecordM a -> m (Either TLSError a)
runRxState ctx f = do
    ver <- usingState_ ctx getVersion
    liftIO $ modifyMVar (ctxRxState ctx) $ \st ->
        case runRecordM f ver st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

getStateRNG :: (MonadThrow m, MonadIO m) => Context m -> Int -> m Bytes
getStateRNG ctx n = usingState_ ctx $ genRandom n

withReadLock :: (MonadMask m, MonadIO m) => Context m -> m a -> m a
withReadLock ctx f = withMVar' (ctxLockRead ctx) (const f)

withWriteLock :: (MonadMask m, MonadIO m) => Context m -> m a -> m a
withWriteLock ctx f = withMVar' (ctxLockWrite ctx) (const f)

withRWLock :: (MonadMask m, MonadIO m) => Context m -> m a -> m a
withRWLock ctx f = withReadLock ctx $ withWriteLock ctx f

withStateLock :: (MonadMask m, MonadIO m) => Context m -> m a -> m a
withStateLock ctx f = withMVar' (ctxLockState ctx) (const f)


withMVar' :: (MonadMask m, MonadIO m) => MVar a -> (a -> m b) -> m b
withMVar' m io =
  mask $ \restore -> do
    a <- liftIO $ takeMVar m
    b <- restore (io a) `onException` (liftIO $ putMVar m a)
    liftIO $ putMVar m a
    return b
