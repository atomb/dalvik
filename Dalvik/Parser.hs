module Dalvik.Parser where

import Control.Applicative
import Control.Monad
import Data.Bits
import qualified Data.ByteString as BS
import Data.Int
import Data.Serialize.Get
import Data.Word

{-
Based on documentation from:
    http://netmite.com/android/mydroid/dalvik/docs/dex-format.htm
-}

data DexHeader =
  DexHeader
  { dexMagic        :: BS.ByteString
  , dexVersion      :: BS.ByteString
  , dexChecksum     :: Word32
  , dexSHA1         :: [Word8]
  , dexFileLen      :: Word32
  , dexHdrLen       :: Word32
  , dexLinkSize     :: Word32
  , dexLinkOff      :: Word32
  , dexMapOff       :: Word32
  , dexNumStrings   :: Word32
  , dexOffStrings   :: Word32
  , dexNumTypes     :: Word32
  , dexOffTypes     :: Word32
  , dexNumProtos    :: Word32
  , dexOffProtos    :: Word32
  , dexNumFields    :: Word32
  , dexOffFields    :: Word32
  , dexNumMethods   :: Word32
  , dexOffMethods   :: Word32
  , dexNumClassDefs :: Word32
  , dexOffClassDefs :: Word32
  , dexDataSize     :: Word32
  , dexDataOff      :: Word32
  } deriving (Show)

data DexFile =
  DexFile
  { dexHeader :: DexHeader
  } deriving (Show)

loadDexIO :: String -> IO (Either String DexFile)
loadDexIO f = loadDex <$> BS.readFile f

loadDex :: BS.ByteString -> Either String DexFile
loadDex bs = do
  h <- runGet parseDexHeader bs
  doSection (dexMapOff h) 0 parseMap bs
  doSection (dexOffStrings h) (dexNumStrings h) parseStrings bs
  doSection (dexOffTypes h) (dexNumTypes h) parseTypes bs
  doSection (dexOffProtos h) (dexNumProtos h) parseProtos bs
  doSection (dexOffFields h) (dexNumFields h) parseFields bs
  doSection (dexOffMethods h) (dexNumMethods h) parseMethods bs
  doSection (dexOffClassDefs h) (dexNumClassDefs h) parseClassDefs bs
  doSection (dexDataOff h) (dexDataSize h) parseData bs
  doSection (dexLinkOff h) (dexLinkSize h) parseLinkInfo bs
  return $ DexFile h

doSection :: Word32 -> Word32 -> (Word32 -> Get a) -> BS.ByteString
          -> Either String a
doSection off size p = runGet (p size) . BS.drop (fromIntegral off)

{- Header parsing -}

parseDexHeader :: Get DexHeader
parseDexHeader = do
  magic <- getBytes 4
  unless (magic == s "dex\n") $ fail "Invalid magic string"
  version <- getBytes 4
  unless (version == s "035\0") $ fail "Unsupported version"
  checksum <- getWord32le
  sha1 <- BS.unpack <$> getBytes 20
  fileLen <- getWord32le
  hdrLen <- getWord32le
  unless (hdrLen == 112) $ fail "Invalid header length"
  endianTag <- getWord32le
  -- TODO: support 0x78563412
  unless (endianTag == 0x12345678) $ fail "Unsupported endianness"
  linkSize <- getWord32le
  linkOff <- getWord32le
  mapOff <- getWord32le
  numStrings <- getWord32le
  offStrings <- getWord32le
  numTypes <- getWord32le
  offTypes <- getWord32le
  numProtos <- getWord32le
  offProtos <- getWord32le
  numFields <- getWord32le
  offFields <- getWord32le
  numMethods <- getWord32le
  offMethods <- getWord32le
  numClassDefs <- getWord32le
  offClassDefs <- getWord32le
  dataSize <- getWord32le
  dataOff <- getWord32le
  return $ DexHeader
           { dexMagic = magic
           , dexVersion = version
           , dexChecksum = checksum
           , dexSHA1 = sha1
           , dexFileLen = fileLen
           , dexHdrLen = hdrLen
           , dexLinkSize = linkSize
           , dexLinkOff = linkOff
           , dexMapOff = mapOff
           , dexNumStrings = numStrings
           , dexOffStrings = offStrings
           , dexNumTypes = numTypes
           , dexOffTypes = offTypes
           , dexNumProtos = numProtos
           , dexOffProtos = offProtos
           , dexNumFields = numFields
           , dexOffFields = offFields
           , dexNumMethods = numMethods
           , dexOffMethods = offMethods
           , dexNumClassDefs = numClassDefs
           , dexOffClassDefs = offClassDefs
           , dexDataSize = dataSize
           , dexDataOff = dataOff
           }

{- Section parsing -}

parseMap :: Word32 -> Get ()
parseMap _ = do
  size <- getWord32le
  items <- replicateM (fromIntegral size) parseMapItem
  return ()

parseMapItem :: Get ()
parseMapItem = do
  itemType <- getWord16le
  unused <- getWord16le
  itemSize <- getWord32le
  itemOff <- getWord32le
  return ()

parseStrings :: Word32 -> Get ()
parseStrings size = return () -- TODO

parseStringDataItem :: Get ()
parseStringDataItem = do
  len <- getULEB128
  str <- getString
  return ()

getString :: Get [Word8]
getString = do
  b <- getWord8
  if b == 0 then return [] else (b:) <$> getString

parseTypes :: Word32 -> Get ()
parseTypes size = return () -- TODO

parseProtos :: Word32 -> Get ()
parseProtos size = return () -- TODO

parseFields :: Word32 -> Get ()
parseFields size = return () -- TODO

parseMethods :: Word32 -> Get ()
parseMethods size = return () -- TODO

parseClassDefs :: Word32 -> Get ()
parseClassDefs size = return () -- TODO

parseData :: Word32 -> Get ()
parseData size = return () -- TODO

parseLinkInfo :: Word32 -> Get ()
parseLinkInfo size = return () -- TODO

{- Utility functions -}

s :: String -> BS.ByteString
s = BS.pack . map toEnum . map fromEnum

{- LEB128 decoding -}

getSLEB128 :: Get Int32
getSLEB128 = do
  (a, n) <- smashLEB <$> getLEB
  let a' | a .&. (1 `shiftL` n) == 0 = a
         | otherwise = a .|. (0xFFFFFFFF `shiftL` n)
  return $ fromIntegral a'

getULEB128 :: Get Word32
getULEB128 = fst <$> smashLEB <$> getLEB

getULEB128p1 :: Get Int32
getULEB128p1 = (pred . fromIntegral) <$> getULEB128

smashLEB :: [Word8] -> (Word32, Int)
smashLEB = go 0 0
  where go a n [] = (a, n - 1)
        go a n (x : xs) = go ((x' `shiftL` n) .|. a) (n + 7) xs
          where x' = fromIntegral x

getLEB :: Get [Word8]
getLEB = do
  b <- getWord8
  ((b .&. 0x7F) :) <$> if (b .&. 0x80) /= 0 then getLEB else return []
