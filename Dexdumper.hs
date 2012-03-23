module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import System.Environment
import Text.Printf

import Dalvik.Parser

processFile :: FilePath -> IO ()
processFile f = do
  putStrLn $ "Processing '" ++ f ++ "'"
  edex <- loadDexIO f
  case edex of
    Left err -> putStrLn err
    Right dex -> do
      mapM_ putStrLn . hdrLines f . dexHeader $ dex

hdrLines f hdr =
  [ printf "Opened '%s', DEX version %s"
    f (show (dexVersion hdr))
  , "DEX file header:"
  , fld "magic" $
    show (BS.append (dexMagic hdr) (dexVersion hdr))
  , fld "checksum" . h8 . dexChecksum $ hdr
  , fld "signature" $ sig (dexSHA1 hdr)
  , fldn "file_size" $ dexFileLen hdr
  , fldn "header_size" $ dexHdrLen hdr
  , fldn "link_size" $ dexLinkSize hdr
  , fldx "link_off" $ dexLinkOff hdr
  , fldn "string_ids_size" $ dexNumStrings hdr
  , fldx "string_ids_off" $ dexOffStrings hdr
  , fldn "type_ids_size" $ dexNumTypes hdr
  , fldx "type_ids_off" $ dexOffTypes hdr
  , fldn "field_ids_size" $ dexNumFields hdr
  , fldx "field_ids_off" $ dexOffFields hdr
  , fldn "method_ids_size" $ dexNumMethods hdr
  , fldx "method_ids_off" $ dexOffMethods hdr
  , fldn "class_defs_size" $ dexNumClassDefs hdr
  , fldx "class_defs_off" $ dexOffClassDefs hdr
  , fldn "data_size" $ dexDataSize hdr
  , fldx "data_off" $ dexDataOff hdr
  ]
  where fld :: String -> String -> String
        fld = printf "%-20s: %s"
        fldx n v = fld n (printf "%d (0x%06x)" v v)
        fldn n v = fld n (show v)
        h8 = printf "%08x"
        sig s = concat [ take 4 s' , "..." , drop 36 s' ]
          where s' = concatMap (printf "%02x") s


main :: IO ()
main = mapM_ processFile =<< getArgs
