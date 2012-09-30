module Dalvik.Apk where

import Codec.Archive.Zip
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Conduit.List
import System.IO

import Dalvik.Parser
import Dalvik.Types

lazyToStrictBS :: LBS.ByteString -> BS.ByteString
lazyToStrictBS = BS.concat . LBS.toChunks

loadDexFromApkIO :: FilePath -> IO (Either String DexFile)
loadDexFromApkIO f = do
  chunks <- withArchive f (sourceEntry "classes.dex" consume)
  -- TODO: this is silly. Should we tweak the parser to work with
  -- lazy ByteStrings?
  return . loadDex . BS.concat $ chunks

loadDexFromAnyIO :: FilePath -> IO (Either String DexFile)
loadDexFromAnyIO f = do
  h <- openFile f ReadMode
  c <- hGetChar h
  hClose h
  case c of
    'P' -> loadDexFromApkIO f
    'd' -> loadDexIO f
    _ -> return (Left "Invalid file format")
