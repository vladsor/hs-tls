module Network.TLS.Crypto
	( HashType(..)
	, HashCtx

	-- * incremental interface with algorithm type wrapping for genericity
	, initHash
	, updateHash
	, finalizeHash

	-- * single pass lazy bytestring interface for each algorithm
	, hashMD5
	, hashSHA1
	-- * incremental interface for each algorithm
	, initMD5
	, updateMD5
	, finalizeMD5
	, initSHA1
	, updateSHA1
	, finalizeSHA1

	-- * RSA stuff
	, PublicKey(..)
	, PrivateKey(..)
	, rsaEncrypt
	, rsaDecrypt
	) where

import qualified Data.CryptoHash.SHA1 as SHA1
import qualified Data.CryptoHash.MD5 as MD5
import qualified Data.ByteString as B
import Data.ByteString.Lazy (ByteString)
import Codec.Crypto.RSA (PublicKey(..), PrivateKey(..))
import qualified Codec.Crypto.RSA as RSA
import Control.Spoon
import Random

data HashCtx =
	  SHA1 !SHA1.Ctx
	| MD5 !MD5.Ctx

instance Show HashCtx where
	show (SHA1 _) = "sha1"
	show (MD5 _) = "md5"

data HashType = HashTypeSHA1 | HashTypeMD5

{- MD5 -}

initMD5 :: MD5.Ctx
initMD5 = MD5.init

updateMD5 :: MD5.Ctx -> B.ByteString -> MD5.Ctx
updateMD5 = MD5.update

finalizeMD5 :: MD5.Ctx -> B.ByteString
finalizeMD5 = MD5.finalize

hashMD5 :: ByteString -> B.ByteString
hashMD5 = MD5.hashlazy

{- SHA1 -}

initSHA1 :: SHA1.Ctx
initSHA1 = SHA1.init

updateSHA1 :: SHA1.Ctx -> B.ByteString -> SHA1.Ctx
updateSHA1 = SHA1.update

finalizeSHA1 :: SHA1.Ctx -> B.ByteString
finalizeSHA1 = SHA1.finalize

hashSHA1 :: ByteString -> B.ByteString
hashSHA1 = SHA1.hashlazy

{- generic Hashing -}

initHash :: HashType -> HashCtx
initHash HashTypeSHA1 = SHA1 (initSHA1)
initHash HashTypeMD5  = MD5 (initMD5)

updateHash :: HashCtx -> B.ByteString -> HashCtx
updateHash (SHA1 ctx) = SHA1 . updateSHA1 ctx
updateHash (MD5 ctx)  = MD5 . updateMD5 ctx

finalizeHash :: HashCtx -> B.ByteString
finalizeHash (SHA1 ctx) = finalizeSHA1 ctx
finalizeHash (MD5 ctx)  = finalizeMD5 ctx

{- RSA reexport and maybification -}

{- on using spoon:
 because we use rsa Encrypt/Decrypt in a pure context, catching the exception
 when the key is not correctly set or the data isn't correct.
 need to fix the RSA package to return "Either String X".
-}

rsaEncrypt :: RandomGen g => g -> PublicKey -> ByteString -> Maybe (ByteString, g)
rsaEncrypt g pk b = teaspoon (RSA.rsaes_pkcs1_v1_5_encrypt g pk b)

rsaDecrypt :: PrivateKey -> ByteString -> Maybe ByteString
rsaDecrypt pk b = teaspoon (RSA.rsaes_pkcs1_v1_5_decrypt pk b)
