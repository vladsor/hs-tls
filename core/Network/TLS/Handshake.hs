-- |
-- Module      : Network.TLS.Handshake
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake
    ( handshake
    , handshakeClientWith
    , handshakeServerWith
    , handshakeClient
    , handshakeServer
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.IO
import Network.TLS.Util (catchException)

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Server

import Control.Monad.State
import Control.Exception (fromException)
import Control.Monad.Catch

-- | Handshake for a new TLS connection
-- This is to be called at the beginning of a connection, and during renegotiation
handshake :: (MonadMask m, MonadIO m) => Context m -> m ()
handshake ctx =
    handleException $ withRWLock ctx (ctxDoHandshake ctx $ ctx)
  where handleException f = catchException f $ \exception -> do
            let tlserror = maybe (Error_Misc $ show exception) id $ fromException exception
            setEstablished ctx False
            sendPacket ctx (errorToAlert tlserror)
            handshakeFailed tlserror
