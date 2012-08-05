{-# LANGUAGE OverloadedStrings #-}
module Main where

import Blaze.ByteString.Builder
import Blaze.Text.Int
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.ByteString.UTF8 as UTF8
import qualified Data.Map as Map
import Data.List
import Data.Maybe
import Data.Monoid
import Data.String
import Data.Word
import System.Environment

import Dalvik.AccessFlags
import Dalvik.Instruction
import Dalvik.Parser
import Dalvik.Printer

processFile :: FilePath -> IO ()
processFile f = do
  putStrLn $ "Processing '" ++ f ++ "'..."
  edex <- loadDexIO f
  case edex of
    Left err -> putStrLn err
    Right dex -> do
      LBS.putStrLn . toLazyByteString . hdrLines f . dexHeader $ dex
      LBS.putStrLn . toLazyByteString . clsLines . dexClasses $ dex
        where clsLines = mconcatLines . map (classLines dex) . Map.toList

escape :: String -> String
escape [] = []
escape ('\0' : s) = '\\' : '0' : escape s
escape ('\n' : s) = '\\' : 'n' : escape s
escape (c : s) = c : escape s

h4' :: (Monoid s, IsString s) => Word32 -> s
h4' = h4 . fromIntegral

mconcatLines :: [Builder] -> Builder
mconcatLines = mconcat . intersperse "\n"

hdrLines :: FilePath -> DexHeader -> Builder
hdrLines f hdr =
  mconcatLines
  [ mconcat
    [ "Opened "
    , fromString (squotes f)
    , ", DEX version "
    , fromString . squotes . escape . UTF8.toString . BS.take 3 $ dexVersion hdr
    ]
  , "DEX file header:"
  , fld "magic" . fromString . squotes . escape .
        UTF8.toString . BS.append (dexMagic hdr) $ dexVersion hdr
  , fld "checksum" . h8 $ dexChecksum hdr
  , fld "signature" . sig $ dexSHA1 hdr
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
  where sig s = mconcat [ mconcat (take 2 s') , "..." , mconcat (drop 18 s') ]
          where s' = map h2 s

fld :: String -> Builder -> Builder
fld n v = mconcat [ fromString (lstr 20 n), ": " , v ]

fldx :: String -> Word32 -> Builder
fldx n v = fld n $ mconcat [ integral v, " (0x", h6 v, ")" ]

fldx4 :: String -> Word32 -> Builder
fldx4 n v =
  fld n $
  mconcat [ integral v, " (0x", h4' v, ")" ]

fldn :: (Integral a, Show a) => String -> a -> Builder
fldn n v = fld n (integral v)

fldxs :: String -> Word32 -> Builder -> Builder
fldxs n v s =
  fld n $ mconcat [ "0x", if v >= 0x10000 then h5 v else h4' v, " (", s, ")" ]

fldns :: String -> Word32 -> Builder -> Builder
fldns n v s = fld n $ mconcat [ integral v, " (", s, ")" ]

classLines :: DexFile -> (TypeId, Class) -> Builder
classLines dex (i, cls) =
  mconcatLines
  [ ""
  , mconcat [ "Class #", integral i, " header:" ]
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
  , mconcat [ "Class #", integral i, "            -" ]
  , fld "  Class descriptor" $ pSDI' $ getTypeName dex (classId cls)
  , fldxs "  Access flags"
    (classAccessFlags cls) (flagsString AClass (classAccessFlags cls))
  , fld "  Superclass" $ pSDI' $ getTypeName dex (classSuperId cls)
  , "  Interfaces        -"
  , mconcatLines (map (interfaceLines dex) (zip [0..] (classInterfaces cls)))
  , "  Static fields     -"
  , mconcatLines (map (fieldLines dex) (zip [0..] (classStaticFields cls)))
  , "  Instance fields   -"
  , mconcatLines (map (fieldLines dex) (zip [0..] (classInstanceFields cls)))
  , "  Direct methods    -"
  , mconcatLines (map (methodLines dex) (zip [0..] (classDirectMethods cls)))
  , "  Virtual methods   -"
  , mconcatLines (map (methodLines dex) (zip [0..] (classVirtualMethods cls)))
  , fldns "  source_file_idx"
    (classSourceNameId cls)
    (pSDI (getStr dex (classSourceNameId cls)))
  ]

interfaceLines :: DexFile -> (Word32, TypeId) -> Builder
interfaceLines dex (n, i) =
  fld ("    #" ++ show n) (pSDI' (getTypeName dex i))

fieldLines :: DexFile -> (Word32, EncodedField) -> Builder
fieldLines dex (n, f) =
  mconcatLines
  [ mconcat
    [ "    #", integral n
    , "              : (in ", clsName, ")" ]
  , fld "      name" . pSDI' . getStr dex . fieldNameId $ field
  , fld "      type" . pSDI' . getTypeName dex . fieldTypeId $ field
  , fldxs "      access"
    (fieldAccessFlags f)
    (flagsString AField (fieldAccessFlags f))
  ] where field = getField dex i
          clsName = pSDI . getTypeName dex . fieldClassId $ field
          i = fieldId f

methodLines :: DexFile -> (Word32, EncodedMethod) -> Builder
methodLines dex (n, m) =
  mconcatLines
  [ mconcat
    [ "    #", integral n , "              : (in " , clsName, ")" ]
  , fld "      name" . pSDI' . getStr dex . methNameId $ method
  , fld "      type" $ squotes $ protoDesc dex proto
  , fldxs "      access"
    (methAccessFlags m)
    (flagsString AMethod (methAccessFlags m))
  , maybe (fromByteString "") (codeLines dex i) (methCode m)
  ] where method = getMethod dex i
          proto = getProto dex (methProtoId method)
          clsName = pSDI . getTypeName dex . methClassId $ method
          i = methId m

codeLines :: DexFile -> MethodId -> CodeItem -> Builder
codeLines dex mid code =
  mconcatLines $
  [ "      code          -"
  , fldn "      registers" $ codeRegs code
  , fldn "      ins" $ codeInSize code
  , fldn "      outs" $ codeOutSize code
  , fld "      insns size" $
    integral (length insnUnits) +++ " 16-bit code units"
  , h6 nameAddr +++ ":                                        |[" +++
    h6 nameAddr +++ "] " +++ methodStr dex mid
  , insnText
  , (fld "      catches" $
   if null tries then "(none)" else integral (length tries))
  ]
  ++
  (map (tryLines dex code) tries)
    where tries = codeTryItems code
          insnUnits = codeInsns code
          insns = decodeInstructions insnUnits
          addr = codeInsnOff code
          nameAddr = addr - 16 -- Ick!
          --insnText = [unwords (map h4 insnUnits)]
          insnText = either
                     (\msg ->
                        (fromString $ "error parsing instructions: " ++ msg))
                     (mconcatLines . insnLines dex addr 0 insnUnits)
                     insns

insnLines :: DexFile -> Word32 -> Word32 -> [Word16] -> [Instruction]
          -> [Builder]
insnLines _ _ _ [] [] = []
insnLines _ _ _ [] is = error $ "Ran out of code units (" ++
                      show is ++ " instructions left)"
insnLines _ _ _ ws [] = error $ "Ran out of instructions (" ++
                      show (length ws) ++ " code units left)"
insnLines dex addr off ws (i:is) =
  mconcat [ h6 addr, ": ", unitStr, "|", h4' off, ": ", istr ] :
  insnLines dex (addr + (l'*2)) (off + l') ws' is
    where (iws, ws') = splitAt l ws
          istrs = map showCodeUnit $ iws
          istrs' | length istrs < 8 = take 8 $ istrs ++ repeat "    "
                 | otherwise = take 7 istrs ++ ["... "]
          l = insnUnitCount i
          l' = fromIntegral l
          unitStr = mconcat . intersperse " " $ istrs'
          showCodeUnit w = h2 (fromIntegral (w .&. 0x00FF)) +++
                           h2 (fromIntegral ((w  .&. 0xFF00) `shiftR` 8))
          istr = insnString dex off i

tryLines :: DexFile -> CodeItem -> TryItem -> Builder
tryLines dex code try =
  mconcatLines
  [ mconcat [ "        0x"
            , h4' (tryStartAddr try)
            ,  " - 0x"
            , h4' end
            ]
  , handlerLines
  , anyLine
  ]
    where end = tryStartAddr try + fromIntegral (tryInsnCount try)
          catches = filter
                    ((== tryHandlerOff try) . fromIntegral . chHandlerOff)
                    (codeHandlers code)
          handlers = mconcat $ map chHandlers catches
          handlerLines = mconcatLines
                         [ mconcat [ "          "
                                   , tyStr
                                   , " -> 0x"
                                   , h4' addr
                                   ] |
                           (ty, addr) <- handlers
                         , let tyStr = pSDI (getTypeName dex ty)
                         ]
          anyLine = mconcat $
                    map
                    (\addr -> "          <any> -> 0x" +++ h4' addr)
                    (mapMaybe chAllAddr catches)

main :: IO ()
main = mapM_ processFile =<< getArgs
