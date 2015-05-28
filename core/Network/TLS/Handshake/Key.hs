-- |
-- Module      : Network.TLS.Handshake.Key
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- functions for RSA operations
--
module Network.TLS.Handshake.Key
    ( encryptRSA
    , signRSA
    , decryptRSA
    , verifyRSA
    , generateDHE
    , generateECDHE
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Handshake.State
import Network.TLS.State (withRNG, getVersion)
import Network.TLS.Crypto
import Network.TLS.Types
import Network.TLS.Context.Internal

import Control.Monad.IO.Class
import Control.Monad.Catch

{- if the RSA encryption fails we just return an empty bytestring, and let the protocol
 - fail by itself; however it would be probably better to just report it since it's an internal problem.
 -}
encryptRSA :: (MonadThrow m, MonadIO m) => Context m -> ByteString -> m ByteString
encryptRSA ctx content = do
    publicKey <- usingHState ctx getRemotePublicKey
    usingState_ ctx $ do
        v      <- withRNG (\g -> kxEncrypt g publicKey content)
        case v of
            Left err       -> fail ("rsa encrypt failed: " ++ show err)
            Right econtent -> return econtent

signRSA :: (MonadThrow m, MonadIO m) => Context m -> Role -> HashDescr -> ByteString -> m ByteString
signRSA ctx _ hsh content = do
    privateKey <- usingHState ctx getLocalPrivateKey
    usingState_ ctx $ do
        r      <- withRNG (\g -> kxSign g privateKey hsh content)
        case r of
            Left err       -> fail ("rsa sign failed: " ++ show err)
            Right econtent -> return econtent

decryptRSA :: (MonadThrow m, MonadIO m) => Context m -> ByteString -> m (Either KxError ByteString)
decryptRSA ctx econtent = do
    privateKey <- usingHState ctx getLocalPrivateKey
    usingState_ ctx $ do
        ver     <- getVersion
        let cipher = if ver < TLS10 then econtent else B.drop 2 econtent
        withRNG (\g -> kxDecrypt g privateKey cipher)

verifyRSA :: MonadIO m => Context m -> Role -> HashDescr -> ByteString -> ByteString -> m Bool
verifyRSA ctx _ hsh econtent sign = do
    publicKey <- usingHState ctx getRemotePublicKey
    return $ kxVerify publicKey hsh econtent sign

generateDHE :: (MonadThrow m, MonadIO m) => Context m -> DHParams -> m (DHPrivate, DHPublic)
generateDHE ctx dhp = usingState_ ctx $ withRNG $ \rng -> dhGenerateKeyPair rng dhp

generateECDHE :: (MonadThrow m, MonadIO m) => Context m -> ECDHParams -> m (ECDHPrivate, ECDHPublic)
generateECDHE ctx dhp = usingState_ ctx $ withRNG $ \rng -> ecdhGenerateKeyPair rng dhp
