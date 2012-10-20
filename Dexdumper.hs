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
      hdrLines f (dexHeader dex)
      mapM_ (classLines dex) . Map.toList . dexClasses $ dex
      p ""

escape :: String -> String
escape [] = []
escape ('\0' : s) = '\\' : '0' : escape s
escape ('\n' : s) = '\\' : 'n' : escape s
escape (c : s) = c : escape s

escapebs :: CBS.ByteString -> CBS.ByteString
escapebs = CBS.pack . escape . CBS.unpack

mconcatLines :: [Builder] -> Builder
mconcatLines = mconcat . intersperse "\n"

pl :: [Builder] -> IO ()
pl = LBS.putStrLn . toLazyByteString . mconcat

p :: Builder -> IO ()
p = LBS.putStrLn . toLazyByteString

hdrLines :: FilePath -> DexHeader -> IO ()
hdrLines f hdr = do
  pl [ "Opened "
     , squotes (CB.fromString f)
     , ", DEX version "
     , squotes . B.fromByteString . escapebs . CBS.take 3 $
       dexVersion hdr
     ]
  p "DEX file header:"
  p $ fld "magic" . squotes . B.fromByteString . escapebs .
          CBS.append (dexMagic hdr) $ dexVersion hdr
  p $ fld "checksum" . fixedHex 8 $ dexChecksum hdr
  p $ fld "signature" . sig $ dexSHA1 hdr
  p $ fldn "file_size" $ dexFileLen hdr
  p $ fldn "header_size" $ dexHdrLen hdr
  p $ fldn "link_size" $ dexLinkSize hdr
  p $ fldx "link_off" $ dexLinkOff hdr
  p $ fldn "string_ids_size" $ dexNumStrings hdr
  p $ fldx "string_ids_off" $ dexOffStrings hdr
  p $ fldn "type_ids_size" $ dexNumTypes hdr
  p $ fldx "type_ids_off" $ dexOffTypes hdr
  p $ fldn "field_ids_size" $ dexNumFields hdr
  p $ fldx "field_ids_off" $ dexOffFields hdr
  p $ fldn "method_ids_size" $ dexNumMethods hdr
  p $ fldx "method_ids_off" $ dexOffMethods hdr
  p $ fldn "class_defs_size" $ dexNumClassDefs hdr
  p $ fldx "class_defs_off" $ dexOffClassDefs hdr
  p $ fldn "data_size" $ dexDataSize hdr
  p $ fldx "data_off" $ dexDataOff hdr
    where sig s = mconcat [ mconcat (take 2 s')
                          , "..."
                          , mconcat (drop 18 s')
                          ]
            where s' = map (fixedHex 2) s

fld :: String -> Builder -> Builder
fld n v = mconcat [ CB.fromString (lstr 20 n), ": " , v ]

fldbroken :: String -> Builder -> Builder
fldbroken n v = mconcat [ CB.fromString n, "              : " , v ]

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

classLines :: DexFile -> (TypeId, Class) -> IO ()
classLines dex (i, cls) = do
  p ""
  pl [ "Class #", integral i, " header:" ]
  p $ fldn "class_idx" $ classId cls
  p $ fldx4 "access_flags" $ classAccessFlags cls
  p $ fldn "superclass_idx" $ classSuperId cls
  p $ fldx "interfaces_off" $ classInterfacesOff cls
  p $ fldn "source_file_idx" $ classSourceNameId cls
  p $ fldx "annotations_off" $ classAnnotsOff cls
  p $ fldx "class_data_off" $ classDataOff cls
  p $ fldn "static_fields_size" $ length (classStaticFields cls)
  p $ fldn "instance_fields_size" $ length (classInstanceFields cls)
  p $ fldn "direct_methods_size" $ length (classDirectMethods cls)
  p $ fldn "virtual_methods_size" $ length (classVirtualMethods cls)
  p $ ""
  pl [ "Class #", integral i, "            -" ]
  p $ fld "  Class descriptor" $ squotes $ getTypeName' dex (classId cls)
  p $ fldxs "  Access flags"
    (classAccessFlags cls) (flagsString AClass (classAccessFlags cls))
  p $ fld "  Superclass" $ squotes $ getTypeName' dex (classSuperId cls)
  p "  Interfaces        -"
  mapM_ (interfaceLines dex) (zip [0..] (classInterfaces cls))
  p "  Static fields     -"
  mapM_ (fieldLines dex) (zip [0..] (classStaticFields cls))
  p "  Instance fields   -"
  mapM_ (fieldLines dex) (zip [0..] (classInstanceFields cls))
  p "  Direct methods    -"
  mapM_ (methodLines dex) (zip [0..] (classDirectMethods cls))
  p "  Virtual methods   -"
  mapM_ (methodLines dex) (zip [0..] (classVirtualMethods cls))
  p $ fldns "  source_file_idx"
    (classSourceNameId cls)
    (getStr' dex (classSourceNameId cls))

interfaceLines :: DexFile -> (Word32, TypeId) -> IO ()
interfaceLines dex (n, i) =
  p $ fldbroken ("    #" ++ show n) (squotes (getTypeName' dex i))

fieldLines :: DexFile -> (Word32, EncodedField) -> IO ()
fieldLines dex (n, f) = do
  pl [ "    #", integral n
     , "              : (in ", clsName, ")" ]
  p $ fld "      name" . squotes . getStr' dex . fieldNameId $ field
  p $ fld "      type" . squotes . getTypeName' dex . fieldTypeId $ field
  p $ fldxs "      access"
      (fieldAccessFlags f)
      (flagsString AField (fieldAccessFlags f))
    where field = getField dex i
          clsName = getTypeName' dex . fieldClassId $ field
          i = fieldId f

methodLines :: DexFile -> (Word32, EncodedMethod) -> IO ()
methodLines dex (n, m) = do
  pl [ "    #", integral n , "              : (in " , clsName, ")" ]
  p $ fld "      name" . squotes . getStr' dex . methNameId $ method
  p $ fld "      type" $ squotes $ protoDesc dex proto
  p $ fldxs "      access" flags (flagsString AMethod flags)
  maybe (p "      code          : (none)\n")
        (codeLines dex flags i)
        (methCode m)
    where method = getMethod dex i
          proto = getProto dex (methProtoId method)
          flags = methAccessFlags m
          clsName = getTypeName' dex . methClassId $ method
          i = methId m

codeLines :: DexFile -> AccessFlags -> MethodId -> CodeItem -> IO ()
codeLines dex flags mid code = do
  p "      code          -"
  p $ fldn "      registers" $ codeRegs code
  p $ fldn "      ins" $ codeInSize code
  p $ fldn "      outs" $ codeOutSize code
  p $ fld "      insns size" $
    integral (length insnUnits) +++ " 16-bit code units"
  p $ fixedHex 6 nameAddr +++ ":                                        |[" +++
    fixedHex 6 nameAddr +++ "] " +++ methodStr dex mid
  insnText
  p $ fld "      catches"
      (if null tries then "(none)" else integral (length tries))
  mapM_ (tryLines dex code) tries
  p $ fld "      positions" ""
  p $ mconcatLines positionText
  p $ fld "      locals" ""
  if Map.null (dbgLocals debugState) then return () else plocals
  p ""
    where tries = codeTryItems code
          insnUnits = codeInsns code
          insns = decodeInstructions insnUnits
          addr = codeInsnOff code
          nameAddr = addr - 16 -- Ick!
          debugState = executeInsns dex code flags mid
          positionText = map ppos . reverse . dbgPositions $ debugState
          ppos (PositionInfo a l) =
            "        0x" +++ fixedHex 4 a +++
            " line=" +++ integral l
          plocals = (mapM_ plocal .
                     sortBy cmpLocal .
                     filter hasName)
                    [ (r, l) | (r, ls) <- Map.toList (dbgLocals debugState)
                             , l <- ls ]
          cmpLocal (_, LocalInfo _ e _ _ _) (_, LocalInfo _ e' _ _ _) =
            compare e e'
          hasName (_, LocalInfo _ _ nid _ _) = nid /= (-1)
          plocal (r, LocalInfo s e nid tid sid) = p $
            "        0x" +++ fixedHex 4 s +++
            " - 0x" +++ fixedHex 4 e +++ " reg=" +++
            integral r +++ " " +++ nstr nid +++ " " +++ tstr tid +++
            " " +++ (if sid == -1 then "" else nstr sid)
          insnText = either
                     (\msg -> p . CB.fromString $
                              "error parsing instructions: " ++ msg)
                     (insnLines dex addr 0 insnUnits)
                     insns
          nstr nid = getStr' dex . fromIntegral $ nid
          tstr tid = getTypeName' dex . fromIntegral $ tid

insnLines :: DexFile -> Word32 -> Word32 -> [Word16] -> [Instruction]
          -> IO ()
insnLines _ _ _ [] [] = return ()
insnLines _ _ _ [] is = error $ "Ran out of code units (" ++
                      show is ++ " instructions left)"
insnLines _ _ _ ws [] = error $ "Ran out of instructions (" ++
                      show (length ws) ++ " code units left)"
insnLines dex addr off ws (i:is) = do
  pl [ fixedHex 6 addr, ": ", unitStr, "|", fixedHex 4 off, ": ", istr ]
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

tryLines :: DexFile -> CodeItem -> TryItem -> IO ()
tryLines dex code try = do
  pl [ "        0x"
     , fixedHex 4 (tryStartAddr try)
     ,  " - 0x"
     , fixedHex 4 end
     ]
  handlerLines
  anyLine
    where end = tryStartAddr try + fromIntegral (tryInsnCount try)
          catches = filter
                    ((== tryHandlerOff try) . fromIntegral . chHandlerOff)
                    (codeHandlers code)
          handlers = mconcat $ map chHandlers catches
          handlerLines = mapM_ p
                         [ mconcat [ "          "
                                   , getTypeName' dex ty
                                   , " -> 0x"
                                   , fixedHex 4 addr
                                   ] |
                           (ty, addr) <- handlers
                         ]
          anyLine = mapM_
                    (\addr -> p $ "          <any> -> 0x" +++ fixedHex 4 addr)
                    (mapMaybe chAllAddr catches)

main :: IO ()
main = mapM_ processFile =<< getArgs
