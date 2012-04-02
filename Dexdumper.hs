module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import qualified Data.Map as Map
import Data.Word
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

pSDI :: StringDataItem -> String
pSDI (SDI _ octs) = UTF8.toString (BS.pack octs)

pSDI' :: StringDataItem -> String
pSDI' (SDI _ octs) = squotes . UTF8.toString . BS.pack $ octs

escape :: String -> String
escape [] = []
escape ('\0' : s) = '\\' : '0' : escape s
escape ('\n' : s) = '\\' : 'n' : escape s
escape (c : s) = c : escape s

squotes :: String -> String
squotes s = "'" ++ s ++ "'"

hdrLines :: FilePath -> DexHeader -> [String]
hdrLines f hdr =
  [ printf "Opened '%s', DEX version '%s'"
    f (escape (UTF8.toString (BS.take 3 (dexVersion hdr))))
  , "DEX file header:"
  , fld "magic" $ squotes $ escape $
    UTF8.toString (BS.append (dexMagic hdr) (dexVersion hdr))
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

fldx :: String -> Word32 -> String
fldx n v = fld n (printf "%d (0x%06x)" v v)

fldx4 :: String -> Word32 -> String
fldx4 n v = fld n (printf "%d (0x%04x)" v v)

fldn :: (Show a) => String -> a -> String
fldn n v = fld n (show v)

fldxs :: String -> Word32 -> String -> String
fldxs n v s = fld n (printf "0x%04x (%s)" v s)

fldns :: String -> Word32 -> String -> String
fldns n v s = fld n (printf "%d (%s)" v s)

getStr :: DexFile -> StringId -> StringDataItem
getStr dex i = Map.findWithDefault (error msg) i (dexStrings dex)
  where msg = printf "Unknown string ID %d" i

getTypeName :: DexFile -> TypeId -> StringDataItem
getTypeName dex i =
  getStr dex (Map.findWithDefault (error msg) i (dexTypeNames dex))
    where msg = printf "Uknown type ID %d" i

getField :: DexFile -> FieldId -> Field
getField dex i = Map.findWithDefault (error msg) i (dexFields dex)
  where msg = printf "Unknown field ID %d" i

getMethod :: DexFile -> MethodId -> Method
getMethod dex i = Map.findWithDefault (error msg) i (dexMethods dex)
  where msg = printf "Unknown method ID %d" i

getProto :: DexFile -> ProtoId -> Proto
getProto dex i = Map.findWithDefault (error msg) i (dexProtos dex)
  where msg = printf "Unknown prototype ID %d" i

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
  , printf "Class #%d            -" i
  , fld "  Class descriptor" $ pSDI' $ getTypeName dex (classId cls)
  , fldxs "  Access flags"
    (classAccessFlags cls) (flagsString AClass (classAccessFlags cls))
  , fld "  Superclass" $ pSDI' $ getTypeName dex (classSuperId cls)
  , "  Interfaces        -"
  ]
  ++ concatMap (interfaceLines dex) (zip [0..] (classInterfaces cls)) ++
  [ "  Static fields     -" ]
  ++ concatMap (fieldLines dex) (zip [0..] (classStaticFields cls)) ++
  [ "  Instance fields   -" ]
  ++ concatMap (fieldLines dex) (zip [0..] (classInstanceFields cls)) ++
  [ "  Direct methods    -" ]
  ++ concatMap (methodLines dex) (zip [0..] (classDirectMethods cls)) ++
  [ "  Virtual methods   -" ]
  ++ concatMap (methodLines dex) (zip [0..] (classVirtualMethods cls)) ++
  [ fldns "  source_file_idx"
    (classSourceNameId cls)
    (pSDI (getStr dex (classSourceNameId cls)))
  ]

interfaceLines :: DexFile -> (Word32, TypeId) -> [String]
interfaceLines dex (n, i) =
  [ fld (printf "    #%d" n) (pSDI' (getTypeName dex i)) ]

fieldLines :: DexFile -> (Word32, EncodedField) -> [String]
fieldLines dex (n, f) =
  [ printf "    #%d              : (in %s)" n clsName
  , fld "      name" . pSDI' . getStr dex . fieldNameId $ field
  , fld "      type" . pSDI' . getTypeName dex . fieldTypeId $ field
  , fldxs "      access"
    (fieldAccessFlags f)
    (flagsString AField (fieldAccessFlags f))
  ] where field = getField dex i
          clsName = pSDI . getTypeName dex . fieldClassId $ field
          i = fieldId f

methodLines :: DexFile -> (Word32, EncodedMethod) -> [String]
methodLines dex (n, m) =
  [ printf "    #%d              : (in %s)" n clsName
  , fld "      name" . pSDI' . getStr dex . methNameId $ method
  , fld "      type" $ protoDesc dex proto
  , fldxs "      access"
    (methAccessFlags m)
    (flagsString AMethod (methAccessFlags m))
  ] ++ maybe [] (codeLines dex) (methCode m)
    where method = getMethod dex i
          proto = getProto dex (methProtoId method)
          clsName = pSDI . getTypeName dex . methClassId $ method
          i = methId m

protoDesc :: DexFile -> Proto -> String
protoDesc dex proto = printf "'(%s)%s'" argStr retStr
  where argStr = concatMap (pSDI . getTypeName dex) (protoParams proto)
        retStr = pSDI $ getTypeName dex (protoRet proto)

codeLines :: DexFile -> CodeItem -> [String]
codeLines dex code =
  [ "      code          -"
  , fldn "      registers" $ codeRegs code
  , fldn "      ins" $ codeInSize code
  , fldn "      outs" $ codeOutSize code
  , fld "      insns size" $
    printf "%d 16-bit code units" (length (codeInsns code))
  ]

main :: IO ()
main = mapM_ processFile =<< getArgs
