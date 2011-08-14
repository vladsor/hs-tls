{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Packet
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Packet module contains everything necessary to serialize and deserialize things
-- with only explicit parameters, no TLS state is involved here.
--
module Network.TLS.Packet
	(
	-- * params for encoding and decoding
	  CurrentParams(..)
	-- * marshall functions for header messages
	, decodeHeader
	, encodeHeader
	, encodeHeaderNoVer -- use for SSL3

	-- * marshall functions for alert messages
	, decodeAlert
	, decodeAlerts
	, encodeAlerts

	-- * marshall functions for handshake messages
	, decodeHandshakes
	, decodeHandshake
	, encodeHandshake
	, encodeHandshakes
	, encodeHandshakeHeader
	, encodeHandshakeContent

	-- * marshall functions for change cipher spec message
	, decodeChangeCipherSpec
	, encodeChangeCipherSpec

	-- * marshall extensions
	, decodeExtSecureRenegotiation
	, encodeExtSecureRenegotiation

	-- * generate things for packet content
	, generateMasterSecret
	, generateKeyBlock
	, generateClientFinished
	, generateServerFinished
	) where

import Network.TLS.Struct
import Network.TLS.Wire
import Network.TLS.Cap
import Data.Either (partitionEithers)
import Data.Maybe (fromJust)
import Data.Bits ((.|.))
import Control.Applicative ((<$>))
import Control.Monad
import Data.Certificate.X509
import Network.TLS.Crypto
import Network.TLS.MAC
import Network.TLS.Cipher (CipherKeyExchangeType(..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD5 as MD5

data CurrentParams = CurrentParams
	{ cParamsVersion     :: Version               -- ^ current protocol version
	, cParamsKeyXchgType :: CipherKeyExchangeType -- ^ current key exchange type
	} deriving (Show,Eq)

runGetErr :: String -> Get a -> ByteString -> Either TLSError a
runGetErr lbl f = either (Left . Error_Packet_Parsing) Right . runGet lbl f

{- marshall helpers -}
getVersion :: Get Version
getVersion = do
	major <- getWord8
	minor <- getWord8
	case verOfNum (major, minor) of
		Nothing -> fail ("invalid version : " ++ show major ++ "," ++ show minor)
		Just v  -> return v

putVersion :: Version -> Put
putVersion ver = putWord8 major >> putWord8 minor
	where (major, minor) = numericalVer ver

getHeaderType :: Get ProtocolType
getHeaderType = do
	ty <- getWord8
	case valToType ty of
		Nothing -> fail ("invalid header type: " ++ show ty)
		Just t  -> return t

putHeaderType :: ProtocolType -> Put
putHeaderType = putWord8 . valOfType

getHandshakeType :: Get HandshakeType
getHandshakeType = do
	ty <- getWord8
	case valToType ty of
		Nothing -> fail ("invalid handshake type: " ++ show ty)
		Just t  -> return t

{-
 - decode and encode headers
 -}
decodeHeader :: ByteString -> Either TLSError Header
decodeHeader = runGetErr "header" $ liftM3 Header getHeaderType getVersion getWord16

encodeHeader :: Header -> ByteString
encodeHeader (Header pt ver len) = runPut (putHeaderType pt >> putVersion ver >> putWord16 len)
	{- FIXME check len <= 2^14 -}

encodeHeaderNoVer :: Header -> ByteString
encodeHeaderNoVer (Header pt _ len) = runPut (putHeaderType pt >> putWord16 len)
	{- FIXME check len <= 2^14 -}

{-
 - decode and encode ALERT
 -}
decodeAlert :: Get (AlertLevel, AlertDescription)
decodeAlert = do
	al <- getWord8
	ad <- getWord8
	case (valToType al, valToType ad) of
		(Just a, Just d) -> return (a, d)
		(Nothing, _)     -> fail "cannot decode alert level"
		(_, Nothing)     -> fail "cannot decode alert description"

decodeAlerts :: ByteString -> Either TLSError [(AlertLevel, AlertDescription)]
decodeAlerts = runGetErr "alerts" $ loop
	where loop = do
		r <- remaining
		if r == 0
			then return []
			else liftM2 (:) decodeAlert loop

encodeAlerts :: [(AlertLevel, AlertDescription)] -> ByteString
encodeAlerts l = runPut $ mapM_ encodeAlert l
	where encodeAlert (al, ad) = putWord8 (valOfType al) >> putWord8 (valOfType ad)

{- decode and encode HANDSHAKE -}
decodeHandshakeHeader :: Get (HandshakeType, Bytes)
decodeHandshakeHeader = do
	ty      <- getHandshakeType
	len     <- getWord24
	content <- getBytes len
	return (ty, content)

decodeHandshakes :: ByteString -> Either TLSError [(HandshakeType, Bytes)]
decodeHandshakes b = runGetErr "handshakes" getAll b where
	getAll = do
		x <- decodeHandshakeHeader
		empty <- isEmpty
		if empty
			then return [x]
			else getAll >>= \l -> return (x : l)

decodeHandshake :: CurrentParams -> HandshakeType -> ByteString -> Either TLSError Handshake
decodeHandshake cp ty = runGetErr "handshake" $ case ty of
	HandshakeType_HelloRequest    -> decodeHelloRequest
	HandshakeType_ClientHello     -> decodeClientHello
	HandshakeType_ServerHello     -> decodeServerHello
	HandshakeType_Certificate     -> decodeCertificates
	HandshakeType_ServerKeyXchg   -> decodeServerKeyXchg cp
	HandshakeType_CertRequest     -> decodeCertRequest cp
	HandshakeType_ServerHelloDone -> decodeServerHelloDone
	HandshakeType_CertVerify      -> decodeCertVerify
	HandshakeType_ClientKeyXchg   -> decodeClientKeyXchg
	HandshakeType_Finished        -> decodeFinished

decodeHelloRequest :: Get Handshake
decodeHelloRequest = return HelloRequest

decodeClientHello :: Get Handshake
decodeClientHello = do
	ver          <- getVersion
	random       <- getClientRandom32
	session      <- getSession
	ciphers      <- getWords16
	compressions <- getWords8
	r            <- remaining
	exts <- if hasHelloExtensions ver && r > 0
		then fmap fromIntegral getWord16 >>= getExtensions
		else return []
	return $ ClientHello ver random session ciphers compressions exts

decodeServerHello :: Get Handshake
decodeServerHello = do
	ver           <- getVersion
	random        <- getServerRandom32
	session       <- getSession
	cipherid      <- getWord16
	compressionid <- getWord8
	r             <- remaining
	exts <- if hasHelloExtensions ver && r > 0
		then fmap fromIntegral getWord16 >>= getExtensions
		else return []
	return $ ServerHello ver random session cipherid compressionid exts

decodeServerHelloDone :: Get Handshake
decodeServerHelloDone = return ServerHelloDone

decodeCertificates :: Get Handshake
decodeCertificates = do
	certs <- getWord24 >>= getCerts >>= return . map (decodeCertificate . L.fromChunks . (:[]))
	let (l, r) = partitionEithers certs
	if length l > 0
		then fail ("error certificate parsing: " ++ show l)
		else return $ Certificates r

decodeFinished :: Get Handshake
decodeFinished = do
	opaque <- remaining >>= getBytes
	return $ Finished $ opaque

getSignatureHashAlgorithm :: Int -> Get [ (HashAlgorithm, SignatureAlgorithm) ]
getSignatureHashAlgorithm 0   = return []
getSignatureHashAlgorithm len = do
	h <- fromJust . valToType <$> getWord8
	s <- fromJust . valToType <$> getWord8
	xs <- getSignatureHashAlgorithm (len - 2)
	return ((h, s) : xs)

decodeCertRequest :: CurrentParams -> Get Handshake
decodeCertRequest cp = do
	certTypes <- map (fromJust . valToType . fromIntegral) <$> getWords8

	sigHashAlgs <- if cParamsVersion cp >= TLS12
		then do
			sighashlen <- getWord16
			Just <$> getSignatureHashAlgorithm (fromIntegral sighashlen)
		else return Nothing
	dNameLen <- getWord16
	when (cParamsVersion cp < TLS12 && dNameLen < 3) $ fail "certrequest distinguishname not of the correct size"
	dName <- getBytes $ fromIntegral dNameLen
	return $ CertRequest certTypes sigHashAlgs (B.unpack dName)

decodeCertVerify :: Get Handshake
decodeCertVerify =
	{- FIXME -}
	return $ CertVerify []

decodeClientKeyXchg :: Get Handshake
decodeClientKeyXchg = do
	ver <- getVersion
	ran <- getClientKeyData46
	return $ ClientKeyXchg ver ran

os2ip :: ByteString -> Integer
os2ip = B.foldl' (\a b -> (256 * a) .|. (fromIntegral b)) 0

decodeServerKeyXchg_DH :: Get ServerDHParams
decodeServerKeyXchg_DH = do
	p <- getWord16 >>= getBytes . fromIntegral
	g <- getWord16 >>= getBytes . fromIntegral
	y <- getWord16 >>= getBytes . fromIntegral
	return $ ServerDHParams { dh_p = os2ip p, dh_g = os2ip g, dh_Ys = os2ip y }

decodeServerKeyXchg_RSA :: Get ServerRSAParams
decodeServerKeyXchg_RSA = do
	modulus <- getWord16 >>= getBytes . fromIntegral
	expo    <- getWord16 >>= getBytes . fromIntegral
	return $ ServerRSAParams { rsa_modulus = os2ip modulus, rsa_exponent = os2ip expo }

decodeServerKeyXchg :: CurrentParams -> Get Handshake
decodeServerKeyXchg cp = do
	skxAlg <- case cParamsKeyXchgType cp of
		CipherKeyExchange_RSA -> do
			rsaparams <- decodeServerKeyXchg_RSA
			return $ SKX_RSA $ Just rsaparams
		CipherKeyExchange_DH_Anon -> do
			dhparams <- decodeServerKeyXchg_DH
			return $ SKX_DH_Anon dhparams
		_ -> do
			bs <- remaining >>= getBytes
			return $ SKX_Unknown bs
	return (ServerKeyXchg skxAlg)

encodeHandshake :: Handshake -> ByteString
encodeHandshake o =
	let content = runPut $ encodeHandshakeContent o in
	let len = fromIntegral $ B.length content in
	let header = runPut $ encodeHandshakeHeader (typeOfHandshake o) len in
	B.concat [ header, content ]

encodeHandshakes :: [Handshake] -> ByteString
encodeHandshakes hss = B.concat $ map encodeHandshake hss

encodeHandshakeHeader :: HandshakeType -> Int -> Put
encodeHandshakeHeader ty len = putWord8 (valOfType ty) >> putWord24 len

encodeHandshakeContent :: Handshake -> Put

encodeHandshakeContent (ClientHello version random session cipherIDs compressionIDs exts) = do
	putVersion version
	putClientRandom32 random
	putSession session
	putWords16 cipherIDs
	putWords8 compressionIDs
	putExtensions exts
	return ()

encodeHandshakeContent (ServerHello version random session cipherID compressionID exts) =
	putVersion version >> putServerRandom32 random >> putSession session
	                   >> putWord16 cipherID >> putWord8 compressionID
	                   >> putExtensions exts >> return ()

encodeHandshakeContent (Certificates certs) =
	putWord24 len >> putBytes certbs
	where
		certbs = runPut $ mapM_ putCert certs
		len    = fromIntegral $ B.length certbs

encodeHandshakeContent (ClientKeyXchg version random) = do
	putVersion version
	putClientKeyData46 random

encodeHandshakeContent (ServerKeyXchg _) = do
	-- FIXME
	return ()

encodeHandshakeContent (HelloRequest) = return ()
encodeHandshakeContent (ServerHelloDone) = return ()

encodeHandshakeContent (CertRequest certTypes sigAlgs certAuthorities) = do
	putWords8 (map valOfType certTypes)
	case sigAlgs of
		Nothing -> return ()
		Just l  -> putWords16 $ map (\(x,y) -> (fromIntegral $ valOfType x) * 256 + (fromIntegral $ valOfType y)) l
	putBytes $ B.pack certAuthorities

encodeHandshakeContent (CertVerify _) = undefined

encodeHandshakeContent (Finished opaque) = putBytes opaque

{- FIXME make sure it return error if not 32 available -}
getRandom32 :: Get Bytes
getRandom32 = getBytes 32

getServerRandom32 :: Get ServerRandom
getServerRandom32 = ServerRandom <$> getRandom32

getClientRandom32 :: Get ClientRandom
getClientRandom32 = ClientRandom <$> getRandom32

putRandom32 :: Bytes -> Put
putRandom32 = putBytes

putClientRandom32 :: ClientRandom -> Put
putClientRandom32 (ClientRandom r) = putRandom32 r

putServerRandom32 :: ServerRandom -> Put
putServerRandom32 (ServerRandom r) = putRandom32 r

getClientKeyData46 :: Get ClientKeyData
getClientKeyData46 = ClientKeyData <$> getBytes 46

putClientKeyData46 :: ClientKeyData -> Put
putClientKeyData46 (ClientKeyData d) = putBytes d

getSession :: Get Session
getSession = do
	len8 <- getWord8
	case fromIntegral len8 of
		0   -> return $ Session Nothing
		len -> Session . Just <$> getBytes len

putSession :: Session -> Put
putSession (Session Nothing)  = putWord8 0
putSession (Session (Just s)) = putWord8 (fromIntegral $ B.length s) >> putBytes s

getCerts :: Int -> Get [Bytes]
getCerts 0   = return []
getCerts len = do
	certlen <- getWord24
	cert <- getBytes certlen
	certxs <- getCerts (len - certlen - 3)
	return (cert : certxs)

putCert :: X509 -> Put
putCert cert = putWord24 (fromIntegral $ B.length content) >> putBytes content
	where content = B.concat $ L.toChunks $ encodeCertificate cert

getExtensions :: Int -> Get [Extension]
getExtensions 0   = return []
getExtensions len = do
	extty <- getWord16
	extdatalen <- getWord16
	extdata <- getBytes $ fromIntegral extdatalen
	extxs <- getExtensions (len - fromIntegral extdatalen - 4)
	return $ (extty, extdata) : extxs

putExtension :: Extension -> Put
putExtension (ty, l) = do
	putWord16 ty
	putWord16 (fromIntegral $ B.length l)
	putBytes l

putExtensions :: [Extension] -> Put
putExtensions [] = return ()
putExtensions es = putWord16 (fromIntegral $ B.length extbs) >> putBytes extbs
	where
		extbs = runPut $ mapM_ putExtension es

{-
 - decode and encode ALERT
 -}

decodeChangeCipherSpec :: ByteString -> Either TLSError ()
decodeChangeCipherSpec = runGetErr "changecipherspec" $ do
	x <- getWord8
	when (x /= 1) (fail "unknown change cipher spec content")

encodeChangeCipherSpec :: ByteString
encodeChangeCipherSpec = runPut (putWord8 1)


{-
 - decode and encode various extensions
 -}
decodeExtSecureRenegotiation :: Bool -> Bytes -> Either TLSError (Bytes, Maybe Bytes)
decodeExtSecureRenegotiation isServerHello = runGetErr "ext-secure-renegotiation" $ do
	l <- fromIntegral <$> getWord8
	if isServerHello
		then do
			cvd <- getBytes (l `div` 2) 
			svd <- getBytes (l `div` 2)
			return (cvd, Just svd)
		else getBytes (l `div` 2) >>= \cvd -> return (cvd, Nothing)

encodeExtSecureRenegotiation :: Bytes -> Maybe Bytes -> Bytes
encodeExtSecureRenegotiation cvd msvd = runPut $ do
	let svd = maybe B.empty id msvd
	putWord8 $ fromIntegral (B.length cvd + B.length svd)
	putBytes cvd
	putBytes svd

{-
 - generate things for packet content
 -}
type PRF = Bytes -> Bytes -> Int -> Bytes

generateMasterSecret_SSL :: Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret_SSL premasterSecret (ClientRandom c) (ServerRandom s) =
	B.concat $ map (computeMD5) ["A","BB","CCC"]
	where
		computeMD5  label = MD5.hash $ B.concat [ premasterSecret, computeSHA1 label ]
		computeSHA1 label = SHA1.hash $ B.concat [ label, premasterSecret, c, s ]

generateMasterSecret_TLS :: PRF -> Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret_TLS prf premasterSecret (ClientRandom c) (ServerRandom s) =
	prf premasterSecret seed 48
	where
		seed = B.concat [ "master secret", c, s ]

generateMasterSecret :: Version -> Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret SSL2  = generateMasterSecret_SSL
generateMasterSecret SSL3  = generateMasterSecret_SSL
generateMasterSecret TLS10 = generateMasterSecret_TLS prf_MD5SHA1
generateMasterSecret TLS11 = generateMasterSecret_TLS prf_MD5SHA1
generateMasterSecret TLS12 = generateMasterSecret_TLS prf_SHA256

generateKeyBlock_TLS :: PRF -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock_TLS prf (ClientRandom c) (ServerRandom s) mastersecret kbsize =
	prf mastersecret seed kbsize where seed = B.concat [ "key expansion", s, c ]

generateKeyBlock_SSL :: ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock_SSL (ClientRandom c) (ServerRandom s) mastersecret kbsize =
	B.concat $ map computeMD5 $ take ((kbsize `div` 16) + 1) labels
	where
		labels            = [ uncurry BC.replicate x | x <- zip [1..] ['A'..'Z'] ]
		computeMD5  label = MD5.hash $ B.concat [ mastersecret, computeSHA1 label ]
		computeSHA1 label = SHA1.hash $ B.concat [ label, mastersecret, s, c ]

generateKeyBlock :: Version -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock SSL2  = generateKeyBlock_SSL
generateKeyBlock SSL3  = generateKeyBlock_SSL
generateKeyBlock TLS10 = generateKeyBlock_TLS prf_MD5SHA1
generateKeyBlock TLS11 = generateKeyBlock_TLS prf_MD5SHA1
generateKeyBlock TLS12 = generateKeyBlock_TLS prf_SHA256

generateFinished_TLS :: PRF -> Bytes -> Bytes -> HashCtx -> HashCtx -> Bytes
generateFinished_TLS prf label mastersecret md5ctx sha1ctx = prf mastersecret seed 12
	where
		seed = B.concat [ label, finalizeHash md5ctx, finalizeHash sha1ctx ]

generateFinished_SSL :: Bytes -> Bytes -> HashCtx -> HashCtx -> Bytes
generateFinished_SSL sender mastersecret md5ctx sha1ctx =
	B.concat [md5hash, sha1hash]
	where
		md5hash  = MD5.hash $ B.concat [ mastersecret, pad2, md5left ]
		sha1hash = SHA1.hash $ B.concat [ mastersecret, B.take 40 pad2, sha1left ]
		md5left  = finalizeHash $ foldl updateHash md5ctx [ sender, mastersecret, pad1 ]
		sha1left = finalizeHash $ foldl updateHash sha1ctx [ sender, mastersecret, B.take 40 pad1 ]
		pad2     = B.replicate 48 0x5c
		pad1     = B.replicate 48 0x36

generateClientFinished :: Version -> Bytes -> HashCtx -> HashCtx -> Bytes
generateClientFinished ver
	| ver < TLS10 = generateFinished_SSL "CLNT"
	| ver < TLS12 = generateFinished_TLS prf_MD5SHA1 "client finished"
	| otherwise   = generateFinished_TLS prf_SHA256 "client finished"

generateServerFinished :: Version -> Bytes -> HashCtx -> HashCtx -> Bytes
generateServerFinished ver
	| ver < TLS10 = generateFinished_SSL "SRVR"
	| ver < TLS12 = generateFinished_TLS prf_MD5SHA1 "server finished"
	| otherwise   = generateFinished_TLS prf_SHA256 "server finished"
