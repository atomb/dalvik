module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import qualified Data.Map as Map
import System.Environment
import Text.Printf

import Dalvik.AccessFlags
import Dalvik.Instruction
import Dalvik.Parser

processFile :: FilePath -> IO ()
processFile f = do
  putStrLn $ "Processing '" ++ f ++ "'..."
  edex <- loadDexIO f
  case edex of
    Left err -> putStrLn err
    Right dex -> do
      mapM_ putStrLn . hdrLines f . dexHeader $ dex
      mapM_ putStrLn . clsLines . dexClasses $ dex
        where clsLines = concat . map (classLines dex) . Map.toList

hdrLines :: FilePath -> DexHeader -> [String]
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
  where h8 = printf "%08x"
        sig s = concat [ take 4 s' , "..." , drop 36 s' ]
          where s' = concatMap (printf "%02x") s

fld :: String -> String -> String
fld = printf "%-20s: %s"
fldx n v = fld n (printf "%d (0x%06x)" v v)
fldx4 n v = fld n (printf "%d (0x%04x)" v v)
fldn n v = fld n (show v)
fldns n v s = fld n (printf "%04x (%s)" v s)
getStr i dex = Map.findWithDefault (SDI 0 []) i (dexStrings dex)
getTypeName i dex = Map.findWithDefault 0 i (dexTypeNames dex)

classLines :: DexFile -> (TypeId, Class) -> [String]
classLines dex (i, cls) =
  [ ""
  , printf "Class #%d header:" i
  , fldn "class_idx" $ classId cls
  , fldx4 "access_flags" $ classAccessFlags cls
  , fldn "superclass_idx" $ classSuperId cls
  , fldx "interfaces_off" $ classInterfacesOff cls
  , fldn "source_file_idx" $ classSourceNameId cls
  , fldx "annotations_off" $ classAnnotsOff cls
  , fldx "class_data_off" $ classDataOff cls
  , fldn "static_fields_size" $ length (classStaticFields cls)
  , fldn "instance_fields_size" $ length (classInstanceFields cls)
  , fldn "direct_methods_size" $ length (classDirectMethods cls)
  , fldn "virtual_methods_size" $ length (classVirtualMethods cls)
  , ""
  , printf "Class #%-13d-" i
  , fld "  Class descriptor" $ showSDI $
    getStr (getTypeName (classId cls) dex) dex
  , fldns "  Access flags"
    (classAccessFlags cls) (flagsString AClass (classAccessFlags cls))
  ]

main :: IO ()
main = mapM_ processFile =<< getArgs
