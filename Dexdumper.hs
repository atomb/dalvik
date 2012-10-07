{-# LANGUAGE OverloadedStrings #-}
module Main ( main ) where

import Data.Bits
import qualified Data.ByteString.Char8 as CBS
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.Map as Map
import Data.List
import Data.Maybe
import Data.Monoid
import Blaze.ByteString.Builder
import Blaze.ByteString.Builder.ByteString as B
import Blaze.ByteString.Builder.Char8 as CB
import Blaze.Text.Int
import Data.Word
import System.Environment

import Dalvik.AccessFlags
import Dalvik.Apk
import Dalvik.DebugInfo
import Dalvik.HexPrint
import Dalvik.Instruction
import Dalvik.Printer
import Dalvik.Types

processFile :: FilePath -> IO ()
processFile f = do
  putStrLn $ "Processing '" ++ f ++ "'..."
  edex <- loadDexFromAnyIO f
  case edex of
    Left err -> putStrLn err
    Right dex -> do
      LBS.putStrLn . toLazyByteString . hdrLines f . dexHeader $ dex
      LBS.putStrLn . toLazyByteString . clsLines . dexClasses $ dex
      LBS.putStrLn ""
        where clsLines = mconcatLines . map (classLines dex) . Map.toList

escape :: String -> String
escape [] = []
escape ('\0' : s) = '\\' : '0' : escape s
escape ('\n' : s) = '\\' : 'n' : escape s
escape (c : s) = c : escape s

escapebs :: CBS.ByteString -> CBS.ByteString
escapebs = CBS.pack . escape . CBS.unpack

mconcatLines :: [Builder] -> Builder
mconcatLines = mconcat . intersperse "\n"

hdrLines :: FilePath -> DexHeader -> Builder
hdrLines f hdr =
  mconcatLines
  [ mconcat
    [ "Opened "
    , squotes (CB.fromString f)
    , ", DEX version "
    , squotes . B.fromByteString . escapebs . CBS.take 3 $
      dexVersion hdr
    ]
  , "DEX file header:"
  , fld "magic" . squotes . B.fromByteString . escapebs .
        CBS.append (dexMagic hdr) $ dexVersion hdr
  , fld "checksum" . fixedHex 8 $ dexChecksum hdr
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
  where sig s = mconcat [ mconcat (take 2 s')
                        , "..."
                        , mconcat (drop 18 s')
                        ]
          where s' = map (fixedHex 2) s

fld :: String -> Builder -> Builder
fld n v = mconcat [ CB.fromString (lstr 20 n), ": " , v ]

fldx :: String -> Word32 -> Builder
fldx n v = fld n $ mconcat [ integral v, " (0x", fixedHex 6 v, ")" ]

fldx4 :: String -> Word32 -> Builder
fldx4 n v =
  fld n $
  mconcat [ integral v, " (0x", fixedHex 4 v, ")" ]

fldn :: (Integral a, Show a) => String -> a -> Builder
fldn n (-1) = fld n "-1"
fldn n v = fld n (integral v)

fldxs :: String -> Word32 -> Builder -> Builder
fldxs n v s =
  fld n $ mconcat [ "0x", fixedHex cs v, " (", s, ")" ]
    where cs = if v >= 0x10000 then 5 else 4

fldns :: String -> Word32 -> Builder -> Builder
fldns n (-1) _ = fld n "-1 (unknown)"
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
  , fld "  Class descriptor" $ squotes $ getTypeName' dex (classId cls)
  , fldxs "  Access flags"
    (classAccessFlags cls) (flagsString AClass (classAccessFlags cls))
  , fld "  Superclass" $ squotes $ getTypeName' dex (classSuperId cls)
  , mconcatLines $
    "  Interfaces        -" :
    map (interfaceLines dex) (zip [0..] (classInterfaces cls))
  , mconcatLines $
    "  Static fields     -" :
    map (fieldLines dex) (zip [0..] (classStaticFields cls))
  , mconcatLines $
    "  Instance fields   -" :
    map (fieldLines dex) (zip [0..] (classInstanceFields cls))
  , mconcatLines $
    "  Direct methods    -" :
    map (methodLines dex) (zip [0..] (classDirectMethods cls))
  , mconcatLines $
    "  Virtual methods   -" :
    map (methodLines dex) (zip [0..] (classVirtualMethods cls))
  , fldns "  source_file_idx"
    (classSourceNameId cls)
    (getStr' dex (classSourceNameId cls))
  ]

interfaceLines :: DexFile -> (Word32, TypeId) -> Builder
interfaceLines dex (n, i) =
  fld ("    #" ++ show n) (squotes (getTypeName' dex i))

fieldLines :: DexFile -> (Word32, EncodedField) -> Builder
fieldLines dex (n, f) =
  mconcatLines
  [ mconcat
    [ "    #", integral n
    , "              : (in ", clsName, ")" ]
  , fld "      name" . squotes . getStr' dex . fieldNameId $ field
  , fld "      type" . squotes . getTypeName' dex . fieldTypeId $ field
  , fldxs "      access"
    (fieldAccessFlags f)
    (flagsString AField (fieldAccessFlags f))
  ] where field = getField dex i
          clsName = getTypeName' dex . fieldClassId $ field
          i = fieldId f

methodLines :: DexFile -> (Word32, EncodedMethod) -> Builder
methodLines dex (n, m) =
  mconcatLines
  [ mconcat
    [ "    #", integral n , "              : (in " , clsName, ")" ]
  , fld "      name" . squotes . getStr' dex . methNameId $ method
  , fld "      type" $ squotes $ protoDesc dex proto
  , fldxs "      access" flags (flagsString AMethod flags)
  , maybe "      code          : (none)\n"
          (codeLines dex flags i)
          (methCode m)
  ] where method = getMethod dex i
          proto = getProto dex (methProtoId method)
          flags = methAccessFlags m
          clsName = getTypeName' dex . methClassId $ method
          i = methId m

codeLines :: DexFile -> AccessFlags -> MethodId -> CodeItem -> Builder
codeLines dex flags mid code =
  mconcatLines
  [ "      code          -"
  , fldn "      registers" $ codeRegs code
  , fldn "      ins" $ codeInSize code
  , fldn "      outs" $ codeOutSize code
  , fld "      insns size" $
    integral (length insnUnits) +++ " 16-bit code units"
  , fixedHex 6 nameAddr +++ ":                                        |[" +++
    fixedHex 6 nameAddr +++ "] " +++ methodStr dex mid
  , insnText
  , mconcatLines $
    fld "      catches"
     (if null tries then "(none)" else integral (length tries)) :
    map (tryLines dex code) tries
  , fld "      positions" ""
  , mconcatLines positionText
  , fld "      locals" ""
  , localsText +++ (if Map.null (dbgLocals debugState) then "" else "\n")
  ]
    where tries = codeTryItems code
          insnUnits = codeInsns code
          insns = decodeInstructions insnUnits
          addr = codeInsnOff code
          nameAddr = addr - 16 -- Ick!
          debugState = executeInsns dex code flags mid
          positionText = map ppos . reverse . dbgPositions $ debugState
          localsText = plocals . dbgLocals $ debugState
          ppos (PositionInfo a l) =
            "        0x" +++ fixedHex 4 a +++
            " line=" +++ integral l
          plocals m = (mconcatLines .
                       map plocal .
                       sortBy cmpLocal .
                       filter hasName)
                      [ (r, l) | (r, ls) <- Map.toList m, l <- ls ]
          cmpLocal (_, LocalInfo _ e _ _ _) (_, LocalInfo _ e' _ _ _) =
            compare e e'
          hasName (_, LocalInfo _ _ nid _ _) = nid /= (-1)
          plocal (r, LocalInfo s e nid tid sid) =
            "        0x" +++ fixedHex 4 s +++
            " - 0x" +++ fixedHex 4 e +++ " reg=" +++
            integral r +++ " " +++ nstr nid +++ " " +++ tstr tid +++
            " " +++ (if sid == -1 then "" else nstr sid)
          insnText = either
                     (\msg ->
                        CB.fromString $ "error parsing instructions: " ++ msg)
                     (mconcatLines . insnLines dex addr 0 insnUnits)
                     insns
          nstr nid = getStr' dex . fromIntegral $ nid
          tstr tid = getTypeName' dex . fromIntegral $ tid

insnLines :: DexFile -> Word32 -> Word32 -> [Word16] -> [Instruction]
          -> [Builder]
insnLines _ _ _ [] [] = []
insnLines _ _ _ [] is = error $ "Ran out of code units (" ++
                      show is ++ " instructions left)"
insnLines _ _ _ ws [] = error $ "Ran out of instructions (" ++
                      show (length ws) ++ " code units left)"
insnLines dex addr off ws (i:is) =
  mconcat [ fixedHex 6 addr, ": ", unitStr, "|", fixedHex 4 off, ": ", istr ] :
  insnLines dex (addr + (l'*2)) (off + l') ws' is
    where (iws, ws') = splitAt l ws
          istrs = map showCodeUnit iws
          istrs' | length istrs < 8 = take 8 $ istrs ++ repeat "    "
                 | otherwise = take 7 istrs ++ ["... "]
          l = insnUnitCount i
          l' = fromIntegral l
          unitStr = mconcat . intersperse " " $ istrs'
          showCodeUnit w = fixedHex 2 (w .&. 0x00FF) +++
                           fixedHex 2 ((w  .&. 0xFF00) `shiftR` 8)
          istr = insnString dex off i

tryLines :: DexFile -> CodeItem -> TryItem -> Builder
tryLines dex code try =
  mconcatLines
  [ mconcat [ "        0x"
            , fixedHex 4 (tryStartAddr try)
            ,  " - 0x"
            , fixedHex 4 end
            ]
  , mconcatLines $ handlerLines ++ anyLine
  ]
    where end = tryStartAddr try + fromIntegral (tryInsnCount try)
          catches = filter
                    ((== tryHandlerOff try) . fromIntegral . chHandlerOff)
                    (codeHandlers code)
          handlers = mconcat $ map chHandlers catches
          handlerLines = [ mconcat [ "          "
                                   , getTypeName' dex ty
                                   , " -> 0x"
                                   , fixedHex 4 addr
                                   ] |
                           (ty, addr) <- handlers
                         ]
          anyLine = map
                    (\addr -> "          <any> -> 0x" +++ fixedHex 4 addr)
                    (mapMaybe chAllAddr catches)

main :: IO ()
main = mapM_ processFile =<< getArgs
