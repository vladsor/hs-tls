{-# LANGUAGE EmptyDataDecls #-}
-- |
-- Module      : Network.TLS.Record.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- The Record Protocol takes messages to be transmitted, fragments the
-- data into manageable blocks, optionally compresses the data, applies
-- a MAC, encrypts, and transmits the result.  Received data is
-- decrypted, verified, decompressed, reassembled, and then delivered to
-- higher-level clients.
--
module Network.TLS.Record.Types
    ( Header(..)
    , ProtocolType(..)
    , packetType
    -- * TLS Records
    , Record(..)
    -- * TLS Record fragment and constructors
    , Fragment
    , fragmentPlaintext
    , fragmentCiphertext
    , fragmentGetBytes
    , Plaintext
    , Compressed
    , Ciphertext
    -- * manipulate record
    , onRecordFragment
    , fragmentCompress
    , fragmentCipher
    , fragmentUncipher
    , fragmentUncompress
    -- * serialize record
    , rawToRecord
    , recordToRaw
    , recordToHeader
    ) where

import Network.TLS.Struct
import Network.TLS.Record.State
import qualified Data.ByteString as B
import Control.Applicative ((<$>))

-- | Represent a TLS record.
data Record a = Record !ProtocolType !Version !(Fragment a) deriving (Show,Eq)

newtype Fragment a = Fragment Bytes deriving (Show,Eq)

data Plaintext
data Compressed
data Ciphertext

fragmentPlaintext :: Bytes -> Fragment Plaintext
fragmentPlaintext bytes = Fragment bytes

fragmentCiphertext :: Bytes -> Fragment Ciphertext
fragmentCiphertext bytes = Fragment bytes

fragmentGetBytes :: Fragment a -> Bytes
fragmentGetBytes (Fragment bytes) = bytes

onRecordFragment :: Record a -> (Fragment a -> RecordM (Fragment b)) -> RecordM (Record b)
onRecordFragment (Record pt ver frag) f = Record pt ver <$> f frag

fragmentMap :: (Bytes -> RecordM Bytes) -> Fragment a -> RecordM (Fragment b)
fragmentMap f (Fragment b) = Fragment <$> f b

-- | turn a plaintext record into a compressed record using the compression function supplied
fragmentCompress :: (Bytes -> RecordM Bytes) -> Fragment Plaintext -> RecordM (Fragment Compressed)
fragmentCompress f = fragmentMap f

-- | turn a compressed record into a ciphertext record using the cipher function supplied
fragmentCipher :: (Bytes -> RecordM Bytes) -> Fragment Compressed -> RecordM (Fragment Ciphertext)
fragmentCipher f = fragmentMap f

-- | turn a ciphertext fragment into a compressed fragment using the cipher function supplied
fragmentUncipher :: (Bytes -> RecordM Bytes) -> Fragment Ciphertext -> RecordM (Fragment Compressed)
fragmentUncipher f = fragmentMap f

-- | turn a compressed fragment into a plaintext fragment using the decompression function supplied
fragmentUncompress :: (Bytes -> RecordM Bytes) -> Fragment Compressed -> RecordM (Fragment Plaintext)
fragmentUncompress f = fragmentMap f

-- | turn a record into an header and bytes
recordToRaw :: Record a -> (Header, Bytes)
recordToRaw (Record pt ver (Fragment bytes)) = (Header pt ver (fromIntegral $ B.length bytes), bytes)

-- | turn a header and a fragment into a record
rawToRecord :: Header -> Fragment a -> Record a
rawToRecord (Header pt ver _) fragment = Record pt ver fragment

-- | turn a record into a header
recordToHeader :: Record a -> Header
recordToHeader (Record pt ver (Fragment bytes)) = Header pt ver (fromIntegral $ B.length bytes)
