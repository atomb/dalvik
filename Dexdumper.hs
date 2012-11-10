{-# LANGUAGE OverloadedStrings #-}
module Main ( main ) where

import Control.Monad
import Data.Bits
import qualified Data.ByteString.Char8 as CBS
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.ByteString.Lazy.Builder as B
import qualified Data.ByteString.Lazy.Builder.ASCII as A
import Data.ByteString.Lazy.Builder (Builder)
import qualified Data.Map as Map
import Data.List
import Data.Maybe
import Data.Monoid
import Data.Word
import System.Environment

import Dalvik.AccessFlags
import Dalvik.Apk
import Dalvik.DebugInfo
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

pl :: [Builder] -> IO ()
pl = LBS.putStrLn . B.toLazyByteString . mconcat

p :: Builder -> IO ()
p = LBS.putStrLn . B.toLazyByteString

word24HexFixed :: Word32 -> Builder
word24HexFixed w = bs +++ ws
  where bs = A.word8HexFixed . fromIntegral $ (w .&. 0x00FF0000) `shiftR` 16
        ws = A.word16HexFixed . fromIntegral $ w .&. 0x0000FFFF

word20HexFixed :: Word32 -> Builder
word20HexFixed w = bs +++ ws
  where bs = A.word8Hex . fromIntegral $ (w .&. 0x000F0000) `shiftR` 16
        ws = A.word16HexFixed . fromIntegral $ w .&. 0x0000FFFF

hdrLines :: FilePath -> DexHeader -> IO ()
hdrLines f hdr = do
  pl [ "Opened "
     , squotes (B.string8 f)
     , ", DEX version "
     , squotes . B.byteString . escapebs . CBS.take 3 $
       dexVersion hdr
     ]
  p "DEX file header:"
  p $ fld "magic" . squotes . B.byteString . escapebs .
          CBS.append (dexMagic hdr) $ dexVersion hdr
  p $ fld "checksum" . A.word32HexFixed $ dexChecksum hdr
  p $ fld "signature" . sig $ dexSHA1 hdr
  p $ fldn32 "file_size" $ dexFileLen hdr
  p $ fldn32 "header_size" $ dexHdrLen hdr
  p $ fldn32 "link_size" $ dexLinkSize hdr
  p $ fldx "link_off" $ dexLinkOff hdr
  p $ fldn32 "string_ids_size" $ dexNumStrings hdr
  p $ fldx "string_ids_off" $ dexOffStrings hdr
  p $ fldn32 "type_ids_size" $ dexNumTypes hdr
  p $ fldx "type_ids_off" $ dexOffTypes hdr
  p $ fldn32 "field_ids_size" $ dexNumFields hdr
  p $ fldx "field_ids_off" $ dexOffFields hdr
  p $ fldn32 "method_ids_size" $ dexNumMethods hdr
  p $ fldx "method_ids_off" $ dexOffMethods hdr
  p $ fldn32 "class_defs_size" $ dexNumClassDefs hdr
  p $ fldx "class_defs_off" $ dexOffClassDefs hdr
  p $ fldn32 "data_size" $ dexDataSize hdr
  p $ fldx "data_off" $ dexDataOff hdr
    where sig s = mconcat [ mconcat (take 2 s')
                          , "..."
                          , mconcat (drop 18 s')
                          ]
            where s' = map A.word8HexFixed s

fld :: String -> Builder -> Builder
fld n v = mconcat [ B.string7 (lstr 20 n), ": " , v ]

fldbroken :: String -> Builder -> Builder
fldbroken n v = mconcat [ B.string7 n, "              : " , v ]

fldx :: String -> Word32 -> Builder
fldx n v = fld n $ mconcat [ A.word32Dec v, " (0x", word24HexFixed v, ")" ]

fldx4 :: String -> Word32 -> Builder
fldx4 n v =
  fld n $
  mconcat [ A.word32Dec v, " (0x", A.word16HexFixed (fromIntegral v), ")" ]

fldn16 :: String -> Word16 -> Builder
fldn16 n (-1) = fld n "-1"
fldn16 n v = fld n (A.word16Dec v)

fldn32 :: String -> Word32 -> Builder
fldn32 n (-1) = fld n "-1"
fldn32 n v = fld n (A.word32Dec v)

fldxs :: String -> Word32 -> Builder -> Builder
fldxs n v s =
  fld n $ mconcat [ "0x", hp v, " (", s, ")" ]
    where hp = if v >= 0x10000
               then word20HexFixed
               else (A.word16HexFixed . fromIntegral)

fldns :: String -> Word32 -> Builder -> Builder
fldns n (-1) _ = fld n "-1 (unknown)"
fldns n v s = fld n $ mconcat [ A.word32Dec v, " (", s, ")" ]

classLines :: DexFile -> (TypeId, Class) -> IO ()
classLines dex (i, cls) = do
  p ""
  pl [ "Class #", A.word16Dec i, " header:" ]
  p $ fldn16 "class_idx" $ classId cls
  p $ fldx4 "access_flags" $ classAccessFlags cls
  p $ fldn16 "superclass_idx" $ classSuperId cls
  p $ fldx "interfaces_off" $ classInterfacesOff cls
  p $ fldn32 "source_file_idx" $ classSourceNameId cls
  p $ fldx "annotations_off" $ classAnnotsOff cls
  p $ fldx "class_data_off" $ classDataOff cls
  p $ fldn32 "static_fields_size" $ fromIntegral $ length (classStaticFields cls)
  p $ fldn32 "instance_fields_size" $ fromIntegral $ length (classInstanceFields cls)
  p $ fldn32 "direct_methods_size" $ fromIntegral $ length (classDirectMethods cls)
  p $ fldn32 "virtual_methods_size" $ fromIntegral $ length (classVirtualMethods cls)
  p $ ""
  pl [ "Class #", A.word16Dec i, "            -" ]
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
  pl [ "    #", A.word32Dec n
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
  pl [ "    #", A.word32Dec n , "              : (in " , clsName, ")" ]
  p $ fld "      name" . squotes . getStr' dex . methNameId $ method
  p $ fld "      type" $ squotes $ protoDesc dex proto
  p $ fldxs "      access" flags (flagsString AMethod flags)
  maybe (p "      code          : (none)" >> p "")
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
  p $ fldn16 "      registers" $ codeRegs code
  p $ fldn16 "      ins" $ codeInSize code
  p $ fldn16 "      outs" $ codeOutSize code
  p $ fld "      insns size" $
    A.word32Dec (fromIntegral (length insnUnits)) +++ " 16-bit code units"
  p $ word24HexFixed nameAddr +++ ":                                        |[" +++
    word24HexFixed nameAddr +++ "] " +++ methodStr dex mid
  insnText
  p $ fld "      catches"
      (if null tries then "(none)" else A.word32Dec (fromIntegral (length tries)))
  mapM_ (tryLines dex code) tries
  p $ fld "      positions" ""
  positionText
  p $ fld "      locals" ""
  unless (Map.null (dbgLocals debugState)) plocals
  p ""
    where tries = codeTryItems code
          insnUnits = codeInsns code
          insns = decodeInstructions insnUnits
          addr = codeInsnOff code
          nameAddr = addr - 16 -- Ick!
          debugState = executeDebugInsns dex code flags mid
          positionText = mapM_ ppos . reverse . dbgPositions $ debugState
          ppos (PositionInfo a l) = p $
            "        0x" +++ A.word16HexFixed (fromIntegral a) +++
            " line=" +++ A.word32Dec l
          plocals = (mapM_ plocal .
                     sortBy cmpLocal .
                     filter hasName)
                    [ (r, l) | (r, ls) <- Map.toList (dbgLocals debugState)
                             , l <- ls ]
          cmpLocal (_, LocalInfo n _ e _ _ _) (_, LocalInfo n' _ e' _ _ _) =
            compare (e, n) (e', n')
          hasName (_, LocalInfo _ _ _ nid _ _) = nid /= (-1)
          plocal (r, LocalInfo _ s e nid tid sid) = p $
            "        0x" +++ A.word16HexFixed (fromIntegral s) +++
            " - 0x" +++ A.word16HexFixed (fromIntegral e) +++ " reg=" +++
            A.word32Dec r +++ " " +++ nstr nid +++ " " +++ tstr tid +++
            " " +++ (if sid == -1 then "" else nstr sid)
          insnText = either
                     (\msg -> p . B.string7 $
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
  pl [ word24HexFixed addr, ": "
     , unitStr, "|"
     , A.word16HexFixed (fromIntegral off), ": "
     , istr
     ]
  insnLines dex (addr + (l'*2)) (off + l') ws' is
    where (iws, ws') = splitAt l ws
          istrs = map showCodeUnit iws
          istrs' | length istrs < 8 = take 8 $ istrs ++ repeat "    "
                 | otherwise = take 7 istrs ++ ["... "]
          l = insnUnitCount i
          l' = fromIntegral l
          unitStr = mconcat . intersperse " " $ istrs'
          showCodeUnit w = A.word8HexFixed (fromIntegral (w .&. 0x00FF)) +++
                           A.word8HexFixed (fromIntegral $ ((w  .&. 0xFF00) `shiftR` 8))
          istr = insnString dex off i

tryLines :: DexFile -> CodeItem -> TryItem -> IO ()
tryLines dex code try = do
  pl [ "        0x"
     , A.word16HexFixed (fromIntegral (tryStartAddr try))
     ,  " - 0x"
     , A.word16HexFixed (fromIntegral end)
     ]
  mapM_ pl [ [ "          "
             , getTypeName' dex ty
             , " -> 0x"
             , A.word16HexFixed (fromIntegral addr)
             ] |
             (ty, addr) <- handlers
           ]
  mapM_ (\addr -> p $ "          <any> -> 0x" +++ A.word16HexFixed (fromIntegral addr))
        (mapMaybe chAllAddr catches)
    where end = tryStartAddr try + fromIntegral (tryInsnCount try)
          catches = filter
                    ((== tryHandlerOff try) . fromIntegral . chHandlerOff)
                    (codeHandlers code)
          handlers = mconcat $ map chHandlers catches

main :: IO ()
main = mapM_ processFile =<< getArgs
