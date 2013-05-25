{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Dalvik.Printer
  ( insnString
  , (+++)
  , pSDI
  , lstr
  , squotes
  , protoDesc
  , methodStr
  , getStr'
  , getTypeName'
  ) where

import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy.Builder as B
import qualified Data.ByteString.Lazy.Builder.ASCII as A
import Data.ByteString.Lazy.Builder (Builder)
import Data.Int
import Data.List
import Data.Monoid
import Data.Serialize.Get ( runGet )
import Data.Serialize.Put ( runPut, putWord32le, putWord64le )
import Data.Serialize.IEEE754 ( getFloat32le, getFloat64le )
import Data.String
import Data.Word
import Text.FShow.RealFloat

import Dalvik.Instruction
import Dalvik.Types

type Str = Builder

instance IsString Builder where
  fromString = B.string7

(+++) :: (Monoid s) => s -> s -> s
(+++) = mappend
{-# INLINE (+++) #-}

lstr :: Int -> String -> String
lstr n s = s ++ replicate (n - length s) ' '

pSDI :: BS.ByteString -> Str
pSDI = B.byteString

squotes :: Str -> Str
squotes s = mconcat [ "'",  s, "'" ]
{-# INLINE squotes #-}

mkInsn :: (Monoid s, IsString s) => s -> [s] -> s
mkInsn name args =
  mconcat [name, " ", mconcat $ intersperse ", " args]
{-# INLINE mkInsn #-}

mkInsn'8 :: Str -> [Word8] -> Str
mkInsn'8 name args = mkInsn name (map iregStr8 args)
{-# INLINE mkInsn'8 #-}

mkInsnb :: (Monoid s, IsString s) => s -> [s] -> [s] -> s
mkInsnb name bargs args =
  mconcat [ name, " {", mconcat (intersperse ", " bargs), "}, "
          , mconcat (intersperse ", " args)
          ]
{-# INLINE mkInsnb #-}

methodComm :: MethodId -> Str
methodComm mid = " // method@" +++ A.word16HexFixed mid

typeComm :: TypeId -> Str
typeComm tid = " // type@" +++ A.word16HexFixed tid

fieldComm :: FieldId -> Str
fieldComm fid = " // field@" +++ A.word16HexFixed fid

stringComm :: StringId -> Str
stringComm sid = " // string@" +++ A.word16HexFixed (fromIntegral sid)

intComm8 :: Word8 -> Str
intComm8 i = " // #" +++ A.word8Hex i

intComm8' :: Word8 -> Str
intComm8' i = " // #" +++ A.word8HexFixed i

intComm16 :: Word16 -> Str
intComm16 i = " // #" +++ A.word16Hex i

intComm16' :: Word16 -> Str
intComm16' i = " // #" +++ A.word16HexFixed i

intComm32 :: Word32 -> Str
intComm32 i = " // #" +++ A.word32HexFixed i

intComm64 :: Word64 -> Str
intComm64 i = " // #" +++ A.word64HexFixed i

offComm :: Int16 -> Str
offComm i = " // " +++ sign +++ A.int16HexFixed i'
  where (sign, i') | i < 0 = ("-", -i)
                   | otherwise = ("+", i)

offComm32 :: Int32 -> Str
offComm32 i = " // " +++ A.int32HexFixed i

offComm' :: Word32 -> Str
offComm' i = " // " +++ sign +++ A.word32HexFixed i'
  where (sign, i') | i < 0 = ("-", -i)
                   | otherwise = ("+", i)
regStr :: Reg -> Str
regStr (R4 r) = iregStr8 r
regStr (R8 r) = iregStr8 r
regStr (R16 r) = iregStr16 r

iregStr8 :: Word8 -> Str
iregStr8 r = "v" +++  A.word8Dec r

iregStr16 :: Word16 -> Str
iregStr16 r = "v" +++  A.word16Dec r

moveTypeString :: (IsString s) => MoveType -> s
moveTypeString MNormal = "move"
moveTypeString MWide = "move-wide"
moveTypeString MObject = "move-object"

moveSizeString :: (IsString s) => Reg -> s
moveSizeString (R4 _) = ""
moveSizeString (R8 _) = "/from16"
moveSizeString (R16 _) = "/16"

constStr :: DexFile -> Str -> Reg -> ConstArg -> Str
constStr dex instr d c = mkInsn instr [regStr d, constString dex c]

ifOpStr :: (IsString s) => IfOp -> s
ifOpStr Eq = "eq"
ifOpStr Ne = "ne"
ifOpStr Lt = "lt"
ifOpStr Ge = "ge"
ifOpStr Gt = "gt"
ifOpStr Le = "le"

typeStr :: (IsString s) => CType -> s
typeStr Byte = "byte"
typeStr Char = "char"
typeStr Short = "short"
typeStr Int = "int"
typeStr Long = "long"
typeStr Float = "float"
typeStr Double = "double"

unopStr :: (IsString s, Monoid s) => Unop -> s
unopStr NegInt = "neg-int"
unopStr NotInt = "not-int"
unopStr NegLong = "neg-long"
unopStr NotLong = "not-long"
unopStr NegFloat = "neg-float"
unopStr NegDouble = "neg-double"
unopStr (Convert ty1 ty2) = mconcat [typeStr ty1, "-to-",  typeStr ty2]

binopStr :: (IsString s) => Binop -> s
binopStr Add = "add"
binopStr Sub = "sub"
binopStr Mul = "mul"
binopStr Div = "div"
binopStr Rem = "rem"
binopStr And = "and"
binopStr Or = "or"
binopStr Xor = "xor"
binopStr Shl = "shl"
binopStr Shr = "shr"
binopStr UShr = "ushr"
binopStr RSub = "rsub"

int32ToFloat :: Int32 -> Float
int32ToFloat =
  either (const (0/0)) id .
  runGet getFloat32le .
  runPut .
  putWord32le .
  fromIntegral

int64ToDouble :: Int64 -> Double
int64ToDouble =
  either (const (0/0)) id .
  runGet getFloat64le .
  runPut .
  putWord64le .
  fromIntegral

ffmt :: Float -> Builder
ffmt f | isNaN f = "nan"
       | otherwise = B.string7 $ fshowFFloat (Just 6) (FF f) ""

dfmt :: Double -> Builder
dfmt d | isNaN d = "nan"
       | otherwise = B.string7 $ fshowFFloat (Just 6) (FD d) ""

constString :: DexFile -> ConstArg -> Str
constString _ (Const4 i) =
  "#int " +++ A.int8Dec (fromIntegral i) +++ intComm8 (fromIntegral i)
constString _ (Const16 i) =
  "#int " +++ A.int16Dec (fromIntegral i) +++ intComm16 (fromIntegral i)
constString _ (ConstHigh16 i) =
  "#int " +++ A.int32Dec i +++
  intComm16 (fromIntegral (i `shiftR` 16) :: Word16)
constString _ (ConstWide16 i) =
  "#int " +++ A.int64Dec i +++ intComm16 (fromIntegral i)
constString _ (Const32 w) =
  -- dexdump always prints these as floats, even though they might not be.
  "#float " +++ ffmt (int32ToFloat w) +++ intComm32 (fromIntegral w :: Word32)
constString _ (ConstWide32 i) =
  -- dexdump always prints these as floats, even though they might not be.
  "#float " +++ ffmt (int32ToFloat (fromIntegral i)) +++
  intComm32 (fromIntegral i)
constString _ (ConstWide w) =
  -- dexdump always prints these as doubles, even though they might not be.
  "#double " +++ dfmt (int64ToDouble w) +++ intComm64 (fromIntegral w)
constString _ (ConstWideHigh16 i) =
  "#long " +++ A.int64Dec i +++
  intComm16 (fromIntegral (i `shiftR` 48) :: Word16)
constString dex (ConstString sid) =
  "\"" +++ getStr' dex sid +++ "\"" +++ stringComm sid
constString dex (ConstStringJumbo sid) =
  "\"" +++ getStr' dex sid +++ "\"" +++ stringComm sid
constString dex (ConstClass tid) =
  getTypeName' dex tid +++ typeComm tid

accessOpStr :: (IsString s, Monoid s) => AccessOp -> s
accessOpStr (Get ty) = "get" +++ accessTypeStr ty
accessOpStr (Put ty) = "put" +++ accessTypeStr ty

accessTypeStr :: (IsString s) => Maybe AccessType -> s
accessTypeStr Nothing = ""
accessTypeStr (Just AWide) = "-wide"
accessTypeStr (Just AObject) = "-object"
accessTypeStr (Just ABoolean) = "-boolean"
accessTypeStr (Just AByte) = "-byte"
accessTypeStr (Just AChar) = "-char"
accessTypeStr (Just AShort) = "-short"

ikindStr :: (IsString s) => InvokeKind -> s
ikindStr Virtual = "virtual"
ikindStr Super = "super"
ikindStr Direct = "direct"
ikindStr Static = "static"
ikindStr Interface = "interface"

getStr' :: DexFile -> StringId -> Str
getStr' _ sid | sid == -1 = "unknown"
getStr' dex sid =
  maybe ("<unknown string ID: " +++ A.word32HexFixed sid +++ ">") pSDI $
  getStr dex sid

getTypeName' :: DexFile -> TypeId -> Str
getTypeName' dex tid =
  maybe ("<unknown type ID: " +++ A.word16HexFixed tid +++ ">") pSDI $
  getTypeName dex tid

getTypeName'' :: DexFile -> TypeId -> Str
getTypeName'' dex tid =
  maybe msg (pSDI . tailSDI) $ getTypeName dex tid
    where tailSDI = BS.map slashToDot . BS.init . BS.tail
          slashToDot 36 = 46
          slashToDot 47 = 46
          slashToDot c = c
          msg = "<unknown type ID: " +++ A.word16HexFixed tid +++ ">"

fieldStr :: DexFile -> FieldId -> Str
fieldStr dex fid =
  case getField dex fid of
    Nothing -> "<unknown field ID: " +++ A.word16HexFixed fid +++ ">"
    Just fld ->
      getTypeName' dex (fieldClassId fld) +++ "." +++
      getStr' dex (fieldNameId fld) +++ ":" +++
      getTypeName' dex (fieldTypeId fld)

protoDesc' :: DexFile -> ProtoId -> Str
protoDesc' dex pid =
  case getProto dex pid of
    Nothing -> "<unknown prototype ID: " +++ A.word16HexFixed pid +++ ">"
    Just proto -> protoDesc dex proto

methodStr :: DexFile -> MethodId -> Str
methodStr dex mid =
  case getMethod dex mid of
    Nothing -> "<unknown method ID: " +++ A.word16HexFixed mid +++ ">"
    Just meth -> getTypeName'' dex (methClassId meth) +++ "." +++
                 getStr' dex (methNameId meth) +++ ":" +++
                 protoDesc' dex (methProtoId meth)

methodStr' :: DexFile -> MethodId -> Str
methodStr' dex mid =
  case getMethod dex mid of
    Nothing -> "<unknown method ID: " +++ A.word16HexFixed mid +++ ">"
    Just meth ->
      getTypeName' dex (methClassId meth) +++ "." +++
      getStr' dex (methNameId meth) +++ ":" +++
      protoDesc' dex (methProtoId meth)

protoDesc :: DexFile -> Proto -> Str
protoDesc dex proto =
  mconcat [ "(", argStr, ")", retStr ]
  where argStr = mconcat $ map (getTypeName' dex) (protoParams proto)
        retStr = getTypeName' dex (protoRet proto)

insnString :: DexFile -> Word32 -> Instruction -> Str
insnString _ _ Nop = "nop" +++ " // spacer"
insnString _ _ (Move mty dst src) =
  mconcat
  [ moveTypeString mty
  , moveSizeString dst, " "
  , regStr dst, ", ", regStr src
  ]
insnString _ _ (Move1 MResult r) = "move-result " +++ regStr r
insnString _ _ (Move1 MResultWide r) = "move-result-wide " +++ regStr r
insnString _ _ (Move1 MResultObject r) = "move-result-object " +++ regStr r
insnString _ _ (Move1 MException r) = "move-exception " +++ regStr r
insnString _ _ ReturnVoid = "return-void"
insnString _ _ (Return MNormal r) = "return " +++ regStr r
insnString _ _ (Return MWide r) = "return-wide " +++ regStr r
insnString _ _ (Return MObject r) = "return-object " +++ regStr r
insnString dex _ (LoadConst d c@(Const4 _)) =
  constStr dex "const/4" d c
insnString dex _ (LoadConst d c@(Const16 _)) =
  constStr dex "const/16" d c
insnString dex _ (LoadConst d c@(ConstHigh16 _)) =
  constStr dex "const/high16" d c
insnString dex _ (LoadConst d c@(ConstWide16 _)) =
  constStr dex "const-wide/16" d c
insnString dex _ (LoadConst d c@(Const32 _)) =
  constStr dex "const" d c
insnString dex _ (LoadConst d c@(ConstWide32 _)) =
  constStr dex "const-wide/32" d c
insnString dex _ (LoadConst d c@(ConstWide _)) =
  constStr dex "const-wide" d c
insnString dex _ (LoadConst d c@(ConstWideHigh16 _)) =
  constStr dex "const-wide/high16" d c
insnString dex _ (LoadConst d c@(ConstString _)) =
  constStr dex "const-string" d c
insnString dex _ (LoadConst d c@(ConstStringJumbo _)) =
  constStr dex "const-string/jumbo" d c
insnString dex _ (LoadConst d c@(ConstClass _)) =
  constStr dex "const-class" d c
insnString _ _ (MonitorEnter r) = "monitor-enter v" +++ A.word8Dec r
insnString _ _ (MonitorExit r) = "monitor-exit v" +++ A.word8Dec r
insnString dex _ (CheckCast r tid) =
  mconcat ["check-cast v", A.word8Dec r,  ", ", getTypeName' dex tid] +++
  typeComm tid
insnString dex _ (InstanceOf dst ref tid) =
  mkInsn "instance-of"
         [ iregStr8 dst, iregStr8 ref, getTypeName' dex tid ] +++
  typeComm tid
insnString _ _ (ArrayLength dst ref) =
  mkInsn'8 "array-length" [ dst, ref ]
insnString dex _ (NewInstance dst tid) =
  mkInsn "new-instance" [ iregStr8 dst, getTypeName' dex tid ] +++
  typeComm tid
insnString dex _ (NewArray dst sz tid) =
  mkInsn "new-array"
         [ iregStr8 dst, iregStr8 sz, getTypeName' dex tid ] +++
  typeComm tid
insnString dex _ (FilledNewArray tid rs) =
  mkInsnb "filled-new-array"
          (map iregStr8 rs) [ getTypeName' dex tid ] +++
  typeComm tid
insnString dex _ (FilledNewArrayRange tid rs) =
  mkInsnb "filled-new-array/range"
          (map iregStr16 rs) [ getTypeName' dex tid ] +++
  typeComm tid
insnString _ a (FillArrayData dst off) =
  mkInsn "fill-array-data"
         [ iregStr8 dst, A.word32HexFixed (a + fromIntegral off) ] +++
  offComm' off
insnString _ _ (Throw r) = "throw v" +++ A.word8Dec r
insnString _ a (Goto off) =
  "goto " +++ A.word16HexFixed (fromIntegral (a + fromIntegral off)) +++
  offComm (fromIntegral off :: Int16)
insnString _ a (Goto16 off) =
  "goto/16 " +++ A.word16HexFixed (fromIntegral (a + fromIntegral off)) +++
  offComm off
insnString _ a (Goto32 off) =
  "goto/32 " +++ A.word32HexFixed (fromIntegral (a + fromIntegral off)) +++
  offComm32 off
insnString _ a (PackedSwitch r off) =
  mkInsn "packed-switch"
         [ iregStr8 r, A.word32HexFixed (a + fromIntegral off) ] +++
  offComm' off
insnString _ a (SparseSwitch r off) =
  mkInsn "sparse-switch"
         [ iregStr8 r, A.word32HexFixed (a + fromIntegral off) ] +++
  offComm' off
insnString _ _ (Cmp CLFloat dst r1 r2) =
  mkInsn'8 "cmpl-float" [dst, r1, r2]
insnString _ _ (Cmp CGFloat dst r1 r2) =
  mkInsn'8 "cmpg-float" [dst, r1, r2]
insnString _ _ (Cmp CLDouble dst r1 r2) =
  mkInsn'8 "cmpl-double" [dst, r1, r2]
insnString _ _ (Cmp CGDouble dst r1 r2) =
  mkInsn'8 "cmpg-double" [dst, r1, r2]
insnString _ _ (Cmp CLong dst r1 r2) =
  mkInsn'8 "cmp-long" [dst, r1, r2]
insnString _ a (If op r1 r2 off) =
  mkInsn ("if-" +++ ifOpStr op)
         [ iregStr8 r1, iregStr8 r2
         , A.word16HexFixed (fromIntegral (a + fromIntegral off))
         ]
  +++ offComm off
insnString _ a (IfZero op r off) =
  mkInsn ("if-" +++ ifOpStr op +++ "z")
         [ iregStr8 r, A.word16HexFixed (fromIntegral (a + fromIntegral off)) ]
  +++ offComm off
insnString _ _ (ArrayOp op val arr idx) =
  mkInsn'8 ("a" +++ accessOpStr op) [ val, arr, idx ]
insnString dex _ (InstanceFieldOp op val obj fid) =
  mkInsn ("i" +++ accessOpStr op)
         [ iregStr8 val, iregStr8 obj, fieldStr dex fid ]
  +++ fieldComm fid
insnString dex _ (StaticFieldOp op val fid) =
  mkInsn ("s" +++ accessOpStr op) [ iregStr8 val, fieldStr dex fid ]
  +++ fieldComm fid
insnString dex _ (Invoke kind range mid args) =
  mkInsn ("invoke-" +++
          ikindStr kind +++
          if range then "/range" else "")
         [ "{" +++
           mconcat (intersperse  ", " (map iregStr16 args)) +++
           "}"
         , methodStr' dex mid
         ] +++
  methodComm mid
insnString _ _ (Unop op r1 r2) =
  mkInsn'8 (unopStr op) [r1, r2]
insnString _ _ (IBinop op False dst r1 r2) =
  mkInsn'8 (binopStr op +++ "-int") [ dst, r1, r2 ]
insnString _ _ (IBinop op True dst r1 r2) =
  mkInsn'8 (binopStr op +++ "-long") [ dst, r1, r2 ]
insnString _ _ (FBinop op False dst r1 r2) =
  mkInsn'8 (binopStr op +++ "-float") [ dst, r1, r2 ]
insnString _ _ (FBinop op True dst r1 r2) =
  mkInsn'8 (binopStr op +++ "-double") [ dst, r1, r2 ]
insnString _ _ (IBinopAssign op False dst src) =
  mkInsn'8 (binopStr op +++ "-int/2addr") [ dst, src ]
insnString _ _ (IBinopAssign op True dst src) =
  mkInsn'8 (binopStr op +++ "-long/2addr") [ dst, src ]
insnString _ _ (FBinopAssign op False dst src) =
  mkInsn'8 (binopStr op +++ "-float/2addr") [ dst, src ]
insnString _ _ (FBinopAssign op True dst src) =
  mkInsn'8 (binopStr op +++ "-double/2addr") [ dst, src ]
insnString _ _ (BinopLit16 RSub dst src i) =
  mkInsn "rsub-int"
         [iregStr8 dst, iregStr8 src, "#int " +++ A.int16Dec i] +++
  intComm16' (fromIntegral i)
insnString _ _ (BinopLit16 op dst src i) =
  mkInsn (binopStr op +++ "-int/lit16")
         [iregStr8 dst, iregStr8 src, "#int " +++ A.int16Dec i] +++
  intComm16' (fromIntegral i)
insnString _ _ (BinopLit8 op dst src i) =
  mkInsn (binopStr op +++ "-int/lit8")
         [iregStr8 dst, iregStr8 src, "#int " +++ A.int8Dec i] +++
  intComm8' (fromIntegral i)
insnString _ _ i@(PackedSwitchData{}) =
  "packed-switch-data (" +++ A.int32Dec (fromIntegral size) +++ " units)"
    where size = insnUnitCount i
insnString _ _ i@(SparseSwitchData{}) =
  "sparse-switch-data (" +++ A.int32Dec (fromIntegral size) +++ " units)"
    where size = insnUnitCount i
insnString _ _ i@(ArrayData{}) =
  "array-data (" +++ A.int32Dec (fromIntegral size) +++ " units)"
    where size = insnUnitCount i
