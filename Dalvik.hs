module Dalvik where

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
loadDex = runGet parseDexFile

parseDexFile :: Get DexFile
parseDexFile = DexFile <$> parseDexHeader

parseDexHeader :: Get DexHeader
parseDexHeader = do
  magic <- getBytes 4
  guard (magic == s "dex\n")
  version <- getBytes 4
  guard (version == s "035\0")
  checksum <- getWord32le
  sha1 <- BS.unpack <$> getBytes 20
  fileLen <- getWord32le
  hdrLen <- getWord32le
  guard (hdrLen == 112)
  endianTag <- getWord32le
  guard (endianTag == 0x12345678) -- TODO: support 0x78563412
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

s :: String -> BS.ByteString
s = BS.pack . map toEnum . map fromEnum

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
