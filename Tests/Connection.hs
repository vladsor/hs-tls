module Tests.Connection
	( newPairContext
	, arbitraryPairParams
	, setPairParamsSessionSaving
	, setPairParamsSessionResuming
	) where

import Test.QuickCheck
import Tests.Certificate
import Tests.PubKey
import Tests.PipeChan
import Network.TLS
import Network.TLS.Core
import Network.TLS.Cipher
import Network.TLS.Crypto
import Control.Concurrent

import qualified Crypto.Random.AESCtr as RNG
import qualified Data.ByteString as B

debug = False

blockCipher :: Cipher
blockCipher = Cipher
	{ cipherID   = 0xff12
	, cipherName = "rsa-id-const"
	, cipherBulk = Bulk
		{ bulkName      = "id"
		, bulkKeySize   = 16
		, bulkIVSize    = 16
		, bulkBlockSize = 16
		, bulkF         = BulkBlockF (\k iv m -> m) (\k iv m -> m)
		}
	, cipherHash = Hash
		{ hashName = "const-hash"
		, hashSize = 16
		, hashF    = (\_ -> B.replicate 16 1)
		}
	, cipherKeyExchange = CipherKeyExchange_RSA
	, cipherMinVer      = Nothing
	}

streamCipher = blockCipher
	{ cipherID   = 0xff13
	, cipherBulk = Bulk
		{ bulkName      = "stream"
		, bulkKeySize   = 16
		, bulkIVSize    = 0
		, bulkBlockSize = 0
		, bulkF         = BulkStreamF (\k -> k) (\i m -> (m,i)) (\i m -> (m,i))
		}
	}

nullCipher = blockCipher
	{ cipherID   = 0xff14
	, cipherBulk = Bulk
		{ bulkName      = "null"
		, bulkKeySize   = 0
		, bulkIVSize    = 0
		, bulkBlockSize = 0
		, bulkF         = BulkNoneF
		}
	}

supportedCiphers :: [Cipher]
supportedCiphers = [blockCipher,streamCipher,nullCipher]

supportedVersions :: [Version]
supportedVersions = [SSL3,TLS10,TLS11,TLS12]

arbitraryPairParams = do
	let (pubKey, privKey) = getGlobalRSAPair
	servCert          <- arbitraryX509WithPublicKey pubKey
	allowedVersions   <- arbitraryVersions
	connectVersion    <- elements supportedVersions `suchThat` (\c -> c `elem` allowedVersions)
	serverCiphers     <- arbitraryCiphers
	clientCiphers     <- oneof [arbitraryCiphers] `suchThat` (\cs -> or [x `elem` serverCiphers | x <- cs])
	secNeg            <- arbitrary

	let serverState = defaultParams
		{ pAllowedVersions        = allowedVersions
		, pCiphers                = serverCiphers
		, pCertificates           = [(servCert, Just $ PrivRSA privKey)]
		, pUseSecureRenegotiation = secNeg
		, pLogging                = logging "server: "
		}
	let clientState = defaultParams
		{ pConnectVersion         = connectVersion
		, pAllowedVersions        = allowedVersions
		, pCiphers                = clientCiphers
		, pUseSecureRenegotiation = secNeg
		, pLogging                = logging "client: "
		}
	return (clientState, serverState)
	where
		logging pre = if debug
			then defaultLogging
				{ loggingPacketSent = putStrLn . ((pre ++ ">> ") ++)
				, loggingPacketRecv = putStrLn . ((pre ++ "<< ") ++) }
			else defaultLogging
		arbitraryVersions :: Gen [Version]
		arbitraryVersions = resize (length supportedVersions + 1) $ listOf1 (elements supportedVersions)
		arbitraryCiphers  = resize (length supportedCiphers + 1) $ listOf1 (elements supportedCiphers)

setPairParamsSessionSaving f (clientState, serverState) = (nc,ns)
	where
		nc = clientState { onSessionEstablished = f }
		ns = serverState { onSessionEstablished = f }

setPairParamsSessionResuming sessionStuff (clientState, serverState) = (nc,ns)
	where
		nc = clientState { sessionResumeWith   = Just sessionStuff }
		ns = serverState { onSessionResumption = \s ->
			return $ if s == fst sessionStuff then Just (snd sessionStuff) else Nothing }

newPairContext pipe (cParams, sParams) = do
	let noFlush = return ()

	cRNG <- RNG.makeSystem
	sRNG <- RNG.makeSystem

	cCtx' <- clientWith cParams cRNG () noFlush (writePipeA pipe) (readPipeA pipe)
	sCtx' <- serverWith sParams sRNG () noFlush (writePipeB pipe) (readPipeB pipe)

	return (cCtx', sCtx')
