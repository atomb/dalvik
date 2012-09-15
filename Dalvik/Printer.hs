{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Dalvik.Printer
  ( insnString
  , (+++)
  , h2
  , h4
  , h5
  , h6
  , h8
  , pSDI
  , pSDI'
  , lstr
  , squotes
  , protoDesc
  , methodStr
  ) where

import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Int
import Data.List
import Data.Monoid
import Data.Serialize.Get ( runGet )
import Data.Serialize.Put ( runPut, putWord32le, putWord64le )
import Data.Serialize.IEEE754 ( getFloat32le, getFloat64le )
import Data.String
import Blaze.ByteString.Builder
import qualified Blaze.ByteString.Builder.Char8 as CB
import Blaze.Text.Int
import Data.Word
import Text.FShow.RealFloat

import Dalvik.HexPrint
import Dalvik.Instruction
import Dalvik.Types

type Str = Builder

instance IsString Builder where
  fromString = fromByteString . fromString

(+++) :: (Monoid s) => s -> s -> s
(+++) = mappend
{-# INLINE (+++) #-}

lstr :: Int -> String -> String
lstr n s = s ++ replicate (n - length s) ' '

pSDI :: StringDataItem -> Str
pSDI (SDI _ t) =  fromByteString t

pSDI' :: StringDataItem -> Str
pSDI' (SDI _ t) = squotes . fromByteString $ t

squotes :: Str -> Str
squotes s = mconcat [ "'",  s, "'" ]
{-# INLINE squotes #-}

mkInsn :: (Monoid s, IsString s) => s -> [s] -> s
mkInsn name args =
  mconcat [name, " ", mconcat $ intersperse ", " args]
{-# INLINE mkInsn #-}

mkInsn' :: (Show a, Integral a) => Str -> [a] -> Str
mkInsn' name args = mkInsn name (map iregStr args)
{-# INLINE mkInsn' #-}

methodComm :: MethodId -> Str
methodComm mid = " // method@" +++ h4 mid

typeComm :: TypeId -> Str
typeComm tid = " // type@" +++ h4 tid

fieldComm :: FieldId -> Str
fieldComm fid = " // field@" +++ h4 fid

stringComm :: StringId -> Str
stringComm sid = " // string@" +++ h4 (fromIntegral sid)

intComm8 :: Int32 -> Str
intComm8 i = " // #" +++ h2 (fromIntegral i)

intComm16 :: Int32 -> Str
intComm16 i = " // #" +++ h4 (fromIntegral i)

intComm32 :: Int32 -> Str
intComm32 i = " // #" +++ h8 (fromIntegral i)

intComm64 :: Int64 -> Str
intComm64 i = " // #" +++ h16 (fromIntegral i)

intComm :: (Integral a) => a -> Str
intComm i = " // #" +++ hexadecimal i

offComm :: (Integral a) => a -> Str
offComm i = " // " +++ sign +++ h4 i'
  where (i', sign) | i < 0 = (-(fromIntegral i), "-")
                   | otherwise = (fromIntegral i, "+")

offComm' :: (Integral a) => a -> Str
offComm' i = " // " +++ sign +++ h8 (fromIntegral i')
  where (i', sign) | i < 0 = (-i, "-")
                   | otherwise = (i, "+")

regStr :: Reg -> Str
regStr (R4 r) = iregStr r
regStr (R8 r) = iregStr r
regStr (R16 r) = iregStr r

iregStr :: (Show a, Integral a) => a -> Str
iregStr r = "v" +++ integral r

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
       | otherwise = CB.fromString $ fshowFFloat (Just 6) (FF f) ""

dfmt :: Double -> Builder
dfmt d | isNaN d = "nan"
       | otherwise = CB.fromString $ fshowFFloat (Just 6) (FD d) ""

constString :: DexFile -> ConstArg -> Str
constString _ (Const4 i) =
  "#int " +++ integral i +++ intComm (fromIntegral i :: Word8)
constString _ (Const16 i) =
  "#int " +++ integral i +++ intComm (fromIntegral i :: Word16)
constString _ (ConstHigh16 i) =
  "#int " +++ integral i +++
  intComm (fromIntegral (i `shiftR` 16) :: Word16)
constString _ (ConstWide16 i) =
  "#int " +++ integral i +++ intComm (fromIntegral i :: Word16)
constString _ (Const32 w) =
  -- dexdump always prints these as floats, even though they might not be.
  "#float " +++ ffmt (int32ToFloat w) +++ intComm32 w
constString _ (ConstWide32 i) =
  -- dexdump always prints these as floats, even though they might not be.
  "#float " +++ ffmt (int32ToFloat (fromIntegral i)) +++
  intComm32 (fromIntegral i)
constString _ (ConstWide w) =
  -- dexdump always prints these as doubles, even though they might not be.
  "#double " +++ dfmt (int64ToDouble w) +++ intComm64 (fromIntegral w)
constString _ (ConstWideHigh16 i) =
  "#long " +++ integral i +++
  intComm (fromIntegral (i `shiftR` 48) :: Word16)
constString dex (ConstString sid) =
  "\"" +++ pSDI (getStr dex sid) +++ "\"" +++ stringComm sid
constString dex (ConstStringJumbo sid) =
  "\"" +++ pSDI (getStr dex sid) +++ "\"" +++ stringComm sid
constString dex (ConstClass tid) =
  (pSDI (getTypeName dex tid)) +++ typeComm tid

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

fieldStr :: DexFile -> FieldId -> Str
fieldStr dex fid = classStr +++ "." +++ fldStr +++ ":" +++ descStr
  where fld = getField dex fid
        classStr = pSDI . getTypeName dex $ fieldClassId fld
        fldStr = pSDI . getStr dex $ fieldNameId fld
        descStr = pSDI . getTypeName dex $ fieldTypeId fld

methodStr :: DexFile -> MethodId -> Str
methodStr dex mid = classStr +++ "." +++ nameStr +++ ":" +++ descStr
  where meth = getMethod dex mid
        classStr = pSDI . tailSDI . getTypeName dex $ methClassId meth
        nameStr = pSDI . getStr dex $ methNameId meth
        descStr = protoDesc dex . getProto dex $ methProtoId meth
        tailSDI (SDI l t) = SDI (l - 2) (BS.map slashToDot . BS.init . BS.tail $ t)
        slashToDot 36 = 46
        slashToDot 47 = 46
        slashToDot c = c

methodStr' :: DexFile -> MethodId -> Str
methodStr' dex mid = classStr +++ "." +++ nameStr +++ ":" +++ descStr
  where meth = getMethod dex mid
        classStr = pSDI . getTypeName dex $ methClassId meth
        nameStr = pSDI . getStr dex $ methNameId meth
        descStr = protoDesc dex . getProto dex $ methProtoId meth

protoDesc :: DexFile -> Proto -> Str
protoDesc dex proto =
  mconcat [ "(", argStr, ")", retStr ]
  where argStr = mconcat $ map (pSDI . getTypeName dex) (protoParams proto)
        retStr = pSDI $ getTypeName dex (protoRet proto)

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
insnString _ _ (MonitorEnter r) = "monitor-enter v" +++ integral r
insnString _ _ (MonitorExit r) = "monitor-exit v" +++ integral r
insnString dex _ (CheckCast r tid) =
  mconcat ["check-cast v", integral r,  ", ", pSDI $ getTypeName dex tid] +++
  typeComm tid
insnString dex _ (InstanceOf dst ref tid) =
  mkInsn "instance-of"
         [ iregStr dst, iregStr ref, pSDI $ getTypeName dex tid ] +++
  typeComm tid
insnString _ _ (ArrayLength dst ref) =
  mkInsn' "array-length" [ dst, ref ]
insnString dex _ (NewInstance dst tid) =
  mkInsn "new-instance" [ iregStr dst, pSDI $ getTypeName dex tid ] +++
  typeComm tid
insnString dex _ (NewArray dst sz tid) =
  mkInsn "new-array"
         [ iregStr dst, iregStr sz, pSDI $ getTypeName dex tid ] +++
  typeComm tid
insnString dex _ (FilledNewArray tid rs) =
  mkInsn "filled-new-array"
         (map iregStr rs ++ [ pSDI $ getTypeName dex tid ]) +++
  typeComm tid
insnString dex _ (FilledNewArrayRange tid rs) =
  mkInsn "filled-new-array/range"
         (map iregStr rs ++ [ pSDI $ getTypeName dex tid ]) +++
  typeComm tid
insnString _ a (FillArrayData dst off) =
  mkInsn "fill-array-data"
         [ iregStr dst, h8 (fromIntegral (a + fromIntegral off)) ] +++
  offComm' off
insnString _ _ (Throw r) = "throw v" +++ integral r
insnString _ a (Goto off) =
  "goto " +++ h4 (fromIntegral (a + fromIntegral off)) +++ offComm off
insnString _ a (Goto16 off) =
  "goto/16 " +++ h4 (fromIntegral (a + fromIntegral off)) +++ offComm off
insnString _ a (Goto32 off) =
  "goto/32 " +++ h8 (fromIntegral (a + fromIntegral off)) +++ offComm off
insnString _ a (PackedSwitch r off) =
  mkInsn "packed-switch"
         [ iregStr r, h8 (fromIntegral (a + fromIntegral off)) ] +++
  offComm' off
insnString _ a (SparseSwitch r off) =
  mkInsn "sparse-switch"
         [ iregStr r, h8 (fromIntegral (a + fromIntegral off)) ] +++
  offComm' off
insnString _ _ (Cmp CLFloat dst r1 r2) =
  mkInsn' "cmpl-float" [dst, r1, r2]
insnString _ _ (Cmp CGFloat dst r1 r2) =
  mkInsn' "cmpg-float" [dst, r1, r2]
insnString _ _ (Cmp CLDouble dst r1 r2) =
  mkInsn' "cmpl-double" [dst, r1, r2]
insnString _ _ (Cmp CGDouble dst r1 r2) =
  mkInsn' "cmpg-double" [dst, r1, r2]
insnString _ _ (Cmp CLong dst r1 r2) =
  mkInsn' "cmp-long" [dst, r1, r2]
insnString _ a (If op r1 r2 off) =
  mkInsn ("if-" +++ ifOpStr op)
         [ iregStr r1, iregStr r2, h4 (fromIntegral (a + fromIntegral off)) ]
  +++ offComm off
insnString _ a (IfZero op r off) =
  mkInsn ("if-" +++ ifOpStr op +++ "z")
         [ iregStr r, h4 (fromIntegral (a + fromIntegral off)) ]
  +++ offComm off
insnString _ _ (ArrayOp op val arr idx) =
  mkInsn' ("a" +++ accessOpStr op) [ val, arr, idx ]
insnString dex _ (InstanceFieldOp op val obj fid) =
  mkInsn ("i" +++ accessOpStr op)
         [ iregStr val, iregStr obj, fieldStr dex fid ]
  +++ fieldComm fid
insnString dex _ (StaticFieldOp op val fid) =
  mkInsn ("s" +++ accessOpStr op) [ iregStr val, fieldStr dex fid ]
  +++ fieldComm fid
insnString dex _ (Invoke kind range mid args) =
  mkInsn ("invoke-" +++
          ikindStr kind +++
          if range then "/range" else "")
         [ "{" +++
           mconcat (intersperse  ", " (map iregStr args)) +++
           "}"
         , methodStr' dex mid
         ] +++
  methodComm mid
insnString _ _ (Unop op r1 r2) =
  mkInsn' (unopStr op) [r1, r2]
insnString _ _ (IBinop op False dst r1 r2) =
  mkInsn' (binopStr op +++ "-int") [ dst, r1, r2 ]
insnString _ _ (IBinop op True dst r1 r2) =
  mkInsn' (binopStr op +++ "-long") [ dst, r1, r2 ]
insnString _ _ (FBinop op False dst r1 r2) =
  mkInsn' (binopStr op +++ "-float") [ dst, r1, r2 ]
insnString _ _ (FBinop op True dst r1 r2) =
  mkInsn' (binopStr op +++ "-double") [ dst, r1, r2 ]
insnString _ _ (IBinopAssign op False dst src) =
  mkInsn' (binopStr op +++ "-int/2addr") [ dst, src ]
insnString _ _ (IBinopAssign op True dst src) =
  mkInsn' (binopStr op +++ "-long/2addr") [ dst, src ]
insnString _ _ (FBinopAssign op False dst src) =
  mkInsn' (binopStr op +++ "-float/2addr") [ dst, src ]
insnString _ _ (FBinopAssign op True dst src) =
  mkInsn' (binopStr op +++ "-double/2addr") [ dst, src ]
insnString _ _ (BinopLit16 op dst src i) =
  mkInsn (binopStr op +++ "-int/lit16")
         [iregStr dst, iregStr src, "#int " +++ integral i] +++
  intComm16 (fromIntegral i)
insnString _ _ (BinopLit8 op dst src i) =
  mkInsn (binopStr op +++ "-int/lit8")
         [iregStr dst, iregStr src, "#int " +++ integral i] +++
  intComm8 (fromIntegral i)
insnString _ _ i@(PackedSwitchData _ _) =
  "packed-switch-data (" +++ integral size +++ " units)"
    where size = insnUnitCount i
insnString _ _ i@(SparseSwitchData _ _) =
  "sparse-switch-data (" +++ integral size +++ " units)"
    where size = insnUnitCount i
insnString _ _ i@(ArrayData _ _ _) =
  "array-data (" +++ integral size +++ " units)"
    where size = insnUnitCount i
