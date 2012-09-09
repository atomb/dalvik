{-# LANGUAGE OverloadedStrings #-}
module Dalvik.Printer where

import Data.Bits
import Data.Int
import Data.List
import Data.Monoid
import Data.Serialize.Get ( runGet )
import Data.Serialize.Put ( runPut, putWord32le, putWord64le )
import Data.Serialize.IEEE754 ( getFloat32le, getFloat64le )
import Data.String
import qualified Data.Text.Lazy as LT
import Data.Text.Lazy.Builder as B
import Data.Text.Lazy.Builder.Int
import Data.Text.Lazy.Builder.RealFloat
import Data.Word
--import Unsafe.Coerce

import Dalvik.Instruction
import Dalvik.Types

type Str = Builder

(+++) :: (Monoid s) => s -> s -> s
(+++) = mappend

hexDigit :: (Integral a, IsString s) => a -> s
hexDigit 0x0 = "0"
hexDigit 0x1 = "1"
hexDigit 0x2 = "2"
hexDigit 0x3 = "3"
hexDigit 0x4 = "4"
hexDigit 0x5 = "5"
hexDigit 0x6 = "6"
hexDigit 0x7 = "7"
hexDigit 0x8 = "8"
hexDigit 0x9 = "9"
hexDigit 0xA = "a"
hexDigit 0xB = "b"
hexDigit 0xC = "c"
hexDigit 0xD = "d"
hexDigit 0xE = "e"
hexDigit 0xF = "f"
hexDigit _   = "?"

h2 :: (IsString s, Monoid s) => Word8 -> s
h2 w =
  mconcat [ hexDigit ((w .&. 0xF0) `shiftR` 4), hexDigit (w .&.  0x0F) ]

h3 :: (IsString s, Monoid s) => Word16 -> s
h3 w =
  mconcat [ hexDigit ((w .&. 0x0F00) `shiftR` 8)
          , hexDigit ((w .&. 0x00F0) `shiftR` 4)
          , hexDigit  (w .&. 0x000F) ]

h4 :: (IsString s, Monoid s) => Word16 -> s
h4 w =
  mconcat [ hexDigit ((w .&. 0xF000) `shiftR` 12)
          , hexDigit ((w .&. 0x0F00) `shiftR` 8)
          , hexDigit ((w .&. 0x00F0) `shiftR` 4)
          , hexDigit  (w .&. 0x000F) ]

h5 :: (IsString s, Monoid s) => Word32 -> s
h5 w =
  mconcat [ hexDigit ((w .&. 0x000F0000) `shiftR` 16)
          , hexDigit ((w .&. 0x0000F000) `shiftR` 12)
          , hexDigit ((w .&. 0x00000F00) `shiftR` 8)
          , hexDigit ((w .&. 0x000000F0) `shiftR` 4)
          , hexDigit  (w .&. 0x0000000F) ]

h6 :: (IsString s, Monoid s) => Word32 -> s
h6 w =
  mconcat [ hexDigit ((w .&. 0x00F00000) `shiftR` 20)
          , hexDigit ((w .&. 0x000F0000) `shiftR` 16)
          , hexDigit ((w .&. 0x0000F000) `shiftR` 12)
          , hexDigit ((w .&. 0x00000F00) `shiftR` 8)
          , hexDigit ((w .&. 0x000000F0) `shiftR` 4)
          , hexDigit  (w .&. 0x0000000F) ]

h7 :: (IsString s, Monoid s) => Word32 -> s
h7 w =
  mconcat [ hexDigit ((w .&. 0x0F000000) `shiftR` 24)
          , hexDigit ((w .&. 0x00F00000) `shiftR` 20)
          , hexDigit ((w .&. 0x000F0000) `shiftR` 16)
          , hexDigit ((w .&. 0x0000F000) `shiftR` 12)
          , hexDigit ((w .&. 0x00000F00) `shiftR` 8)
          , hexDigit ((w .&. 0x000000F0) `shiftR` 4)
          , hexDigit  (w .&. 0x0000000F) ]

h8 :: (IsString s, Monoid s) => Word32 -> s
h8 w =
  mconcat [ hexDigit ((w .&. 0xF0000000) `shiftR` 28)
          , hexDigit ((w .&. 0x0F000000) `shiftR` 24)
          , hexDigit ((w .&. 0x00F00000) `shiftR` 20)
          , hexDigit ((w .&. 0x000F0000) `shiftR` 16)
          , hexDigit ((w .&. 0x0000F000) `shiftR` 12)
          , hexDigit ((w .&. 0x00000F00) `shiftR` 8)
          , hexDigit ((w .&. 0x000000F0) `shiftR` 4)
          , hexDigit  (w .&. 0x0000000F) ]

h16 :: (IsString s, Monoid s) => Word64 -> s
h16 w =
  mconcat [ hexDigit ((w .&. 0xF000000000000000) `shiftR` 60)
          , hexDigit ((w .&. 0x0F00000000000000) `shiftR` 56)
          , hexDigit ((w .&. 0x00F0000000000000) `shiftR` 52)
          , hexDigit ((w .&. 0x000F000000000000) `shiftR` 48)
          , hexDigit ((w .&. 0x0000F00000000000) `shiftR` 44)
          , hexDigit ((w .&. 0x00000F0000000000) `shiftR` 40)
          , hexDigit ((w .&. 0x000000F000000000) `shiftR` 36)
          , hexDigit ((w .&. 0x0000000F00000000) `shiftR` 32)
          , hexDigit ((w .&. 0x00000000F0000000) `shiftR` 28)
          , hexDigit ((w .&. 0x000000000F000000) `shiftR` 24)
          , hexDigit ((w .&. 0x0000000000F00000) `shiftR` 20)
          , hexDigit ((w .&. 0x00000000000F0000) `shiftR` 16)
          , hexDigit ((w .&. 0x000000000000F000) `shiftR` 12)
          , hexDigit ((w .&. 0x0000000000000F00) `shiftR` 8)
          , hexDigit ((w .&. 0x00000000000000F0) `shiftR` 4)
          , hexDigit  (w .&. 0x000000000000000F) ]

hfit :: (Integral a, Bits a, IsString s, Monoid s) => a -> s
hfit a | a == a .&. 0x0000000f = hexDigit a
       | a == a .&. 0x000000ff = h2 (fromIntegral a)
       | a == a .&. 0x00000fff = h3 (fromIntegral a)
       | a == a .&. 0x0000ffff = h4 (fromIntegral a)
       | a == a .&. 0x000fffff = h5 (fromIntegral a)
       | a == a .&. 0x00ffffff = h6 (fromIntegral a)
       | a == a .&. 0x0fffffff = h7 (fromIntegral a)
       | a == a .&. 0xffffffff = h8 (fromIntegral a)
       | otherwise = h16 (fromIntegral a)

lstr :: Int -> String -> String
lstr n s = s ++ replicate (n - length s) ' '

pSDI :: StringDataItem -> Str
pSDI (SDI _ t) =  fromLazyText t

pSDI' :: StringDataItem -> Str
pSDI' (SDI _ t) = squotes . fromLazyText $ t

squotes :: (Monoid s, IsString s) => s -> s
squotes s = mconcat [ "'",  s,  "'" ]

mkInsn :: (Monoid s, IsString s) => s -> [s] -> s
mkInsn name args =
  mconcat [name, " ", mconcat $ intersperse ", " args]

mkInsn' :: (Show a, Integral a) => Str -> [a] -> Str
mkInsn' name args = mkInsn name (map iregStr args)

methodComm :: MethodId -> Str
methodComm mid = " // method@" +++ h4 mid

typeComm :: TypeId -> Str
typeComm tid = " // type@" +++ h4 tid

fieldComm :: FieldId -> Str
fieldComm fid = " // field@" +++ h4 fid

stringComm :: StringId -> Str
stringComm sid = " // string@" +++ h4 (fromIntegral sid)

intComm4 :: Int32 -> Str
intComm4 i = " // #" +++ hexDigit (fromIntegral i :: Word8)

intComm8 :: Int32 -> Str
intComm8 i = " // #" +++ h2 (fromIntegral i)

intComm16 :: Int32 -> Str
intComm16 i = " // #" +++ h4 (fromIntegral i)

intComm32 :: Int32 -> Str
intComm32 i = " // #" +++ h8 (fromIntegral i)

intComm64 :: Int64 -> Str
intComm64 i = " // #" +++ h16 (fromIntegral i)

intComm :: (Integral a, Bits a, IsString s, Monoid s) => a -> s
intComm i = " // #" +++ hfit i

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
iregStr r = "v" +++ decimal r

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

ffmt :: RealFloat a => a -> Builder
ffmt = formatRealFloat Fixed (Just 6)

constString :: DexFile -> ConstArg -> Str
constString _ (Const4 i) =
  "#int " +++ decimal i +++ intComm (fromIntegral i :: Word8)
constString _ (Const16 i) =
  "#int " +++ decimal i +++ intComm (fromIntegral i :: Int16)
constString _ (ConstHigh16 i) =
  "#int " +++ decimal i +++
  intComm (fromIntegral (i `shiftR` 16) :: Int16)
constString _ (ConstWide16 i) =
  "#int " +++ decimal i +++ intComm (fromIntegral i :: Int16)
constString _ (Const32 w) =
  -- dexdump always prints these as floats, even though they might not be.
  "#float " +++ ffmt (int32ToFloat w) +++ intComm32 w
constString _ (ConstWide32 i) =
  -- dexdump always prints these as floats, even though they might not be.
  "#float " +++ ffmt (int32ToFloat (fromIntegral i)) +++
  intComm32 (fromIntegral i)
constString _ (ConstWide w) =
  -- dexdump always prints these as doubles, even though they might not be.
  "#double " +++ ffmt (int64ToDouble w) +++ intComm64 (fromIntegral w)
constString _ (ConstWideHigh16 i) =
  "#long " +++ decimal i +++
  intComm (fromIntegral (i `shiftR` 48) :: Int16)
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
        tailSDI (SDI l t) = SDI (l - 2) (LT.map slashToDot . LT.init . LT.tail $ t)
        slashToDot '$' = '.'
        slashToDot '/' = '.'
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
insnString _ _ (MonitorEnter r) = "monitor-enter v" +++ decimal r
insnString _ _ (MonitorExit r) = "monitor-exit v" +++ decimal r
insnString dex _ (CheckCast r tid) =
  mconcat ["check-cast v", decimal r,  ", ", pSDI $ getTypeName dex tid] +++
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
insnString _ _ (Throw r) = "throw v" +++ decimal r
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
         [iregStr dst, iregStr src, "#int " +++ decimal i] +++
  intComm16 (fromIntegral i)
insnString _ _ (BinopLit8 op dst src i) =
  mkInsn (binopStr op +++ "-int/lit8")
         [iregStr dst, iregStr src, "#int " +++ decimal i] +++
  intComm8 (fromIntegral i)
insnString _ _ i@(PackedSwitchData _ _) =
  "packed-switch-data (" +++ decimal size +++ " units)"
    where size = insnUnitCount i
insnString _ _ i@(SparseSwitchData _ _) =
  "sparse-switch-data (" +++ decimal size +++ " units)"
    where size = insnUnitCount i
insnString _ _ i@(ArrayData _ _ _) =
  "array-data (" +++ decimal size +++ " units)"
    where size = insnUnitCount i
