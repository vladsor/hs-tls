{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}

-- |
-- Module      : Network.TLS.Backend
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A Backend represents a unified way to do IO on different
-- types without burdening our calling API with multiple
-- ways to initialize a new context.
--
-- Typically, a backend provides:
-- * a way to read data
-- * a way to write data
-- * a way to close the stream
-- * a way to flush the stream
--
module Network.TLS.Backend
    ( HasBackend(..)
    , Backend(..)
    ) where

import Control.Monad
import Network.Socket (Socket, sClose)
import qualified Network.Socket.ByteString as Socket
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush, hClose)
import Control.Monad.IO.Class

-- | Connection IO backend
data MonadIO m => Backend m = Backend
    { backendFlush :: m ()                -- ^ Flush the connection sending buffer, if any.
    , backendClose :: m ()                -- ^ Close the connection.
    , backendSend  :: ByteString -> m ()  -- ^ Send a bytestring through the connection.
    , backendRecv  :: Int -> m ByteString -- ^ Receive specified number of bytes from the connection.
    }

class MonadIO m => HasBackend a m where
    initializeBackend :: a -> m ()
    getBackend :: a -> Backend m

instance MonadIO m => HasBackend (Backend m) m where
    initializeBackend _ = return ()
    getBackend = id

instance MonadIO m => HasBackend Socket m where
    initializeBackend _ = return ()
    getBackend sock = Backend (return ()) (liftIO $ sClose sock) (liftIO . Socket.sendAll sock) (liftIO . recvAll)
      where recvAll n = B.concat `fmap` loop n
              where loop 0    = return []
                    loop left = do
                        r <- Socket.recv sock left
                        if B.null r
                            then return []
                            else liftM (r:) (loop (left - B.length r))

instance MonadIO m => HasBackend Handle m where
    initializeBackend handle = liftIO $ hSetBuffering handle NoBuffering
    getBackend handle = Backend (liftIO $ hFlush handle) (liftIO $ hClose handle) (liftIO . B.hPut handle) (liftIO . B.hGet handle)
