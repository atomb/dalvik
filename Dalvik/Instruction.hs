module Dalvik.Instruction where

import Control.Applicative
import Control.Monad.Instances
import Data.Array
import Data.Bits
import Data.Int
import Data.Word

type FieldId = Word16
type MethodId = Word16
type StringId = Word16
type TypeId = Word16

type Word4 = Word8

type Reg4 = Word4
type Reg8 = Word8
type Reg16 = Word16

data Reg
  = R4 Reg4
  | R8 Reg8
  | R16 Reg16

data ConstArg
  = Const4 Int8
  | Const16 Int16
  | ConstHigh16 Int16
  | ConstWide16 Int16
  | Const32 Word32
  | ConstWide32 Int32
  | ConstWide Word64
  | ConstWideHigh16 Int16
  | ConstString Reg8 StringId
  | ConstStringJumbo Reg8 StringId
  | ConstClass Reg8 TypeId

-- TODO: what's the best encoding for move instructions?

data MoveType
  = MNormal
  | MWide
  | MObject

data Move1Type
  = MResult
  | MResultWide
  | MResultObject
  | MException

data AccessType
  = AWide
  | AObject
  | ABoolean
  | AByte
  | AChar
  | AShort

data AccessOp
  = Get (Maybe AccessType)
  | Put (Maybe AccessType)

data InvokeKind
  = Virtual
  | Super
  | Direct
  | Static
  | Interface

data CType
  = Byte
  | Char
  | Short
  | Int
  | Long
  | Float
  | Double

data CmpOp
  = CLFloat
  | CGFloat
  | CLDouble
  | CGDouble
  | CLong

data Unop
  = NegInt
  | NotInt
  | NegLong
  | NotLong
  | NegFloat
  | NegDouble
  | Convert CType CType

data Binop
  = Add
  | Sub
  | Mul
  | Div
  | Rem
  | And
  | Or
  | Xor
  | Shl
  | Shr
  | UShr
  | RSub

data Instruction
  = Nop
  | Move MoveType Reg Reg
  | Move1 Move1Type Reg
  | ReturnVoid
  | Return MoveType Reg
  | Const Reg ConstArg
  | MonitorEnter Reg8
  | MonitorExit Reg8
  | CheckCast Reg8 TypeId
  | InstanceOf Reg4 Reg4 TypeId
  | ArrayLength Reg4 Reg4
  | NewInstance Reg8 TypeId
  | NewArray Reg4 Reg4 TypeId
  {-
  | FilledNewArray
  | FilledNewArrayRange
  | FillArrayData
  -}
  | Throw Reg8
  | Goto Int32
  {-
  | PackedSwitch
  | SparseSwitch
  -}
  {-
  | Cmp
  | If
  | Ifz
  -}
  | ArrayOp AccessOp Reg8 Reg8 Reg8
  | InstanceFieldOp AccessOp Reg4 Reg4 FieldId
  | StaticFieldOp AccessOp Reg8 FieldId
  -- TODO: how best to encode invoke instructions?
  | Invoke InvokeKind Word8 MethodId [Word16]
  | Unop Unop Reg4 Reg4
  | Binop Binop Reg8 Reg8 Reg8
  | BinopAssign Reg4 Reg4
  | BinopLit16 Reg4 Reg4 Int16
  | BinopLit8 Reg8 Reg8 Int8

splitWord8 :: Word8 -> (Word4, Word4)
splitWord8 w = (fromIntegral $ w `shiftR` 4, fromIntegral $ w .&. 0x0F)

splitWord16 :: Word16 -> (Word8, Word8)
splitWord16 w = (fromIntegral $ w `shiftR` 8, fromIntegral $ w .&. 0x00FF)

type DecodeError = String -- TODO: replace with structured type
type IParseResult = Either DecodeError Instruction

invalidOpcode :: Word8 -> DecodeError
invalidOpcode op = "Invalid opcode: " ++ show op

prematureEnd :: Word8 -> DecodeError
prematureEnd op = "Premature end of data stream at opcode: " ++ show op

data InsnParser
  = IParse1 (Word8 -> IParseResult)
  | IParse2 (Word8 -> Word16 -> IParseResult)
  | IParse3 (Word8 -> Word16 -> Word16 -> IParseResult)
  | IParse5 (Word8 -> Word16 -> Word16 -> Word16 -> Word16 -> IParseResult)

-- TOOD: check that ignored rps are zero?
iparseTable :: Array Word8 InsnParser
iparseTable = array (0x00, 0xFF) $
  [ (0x00, noreg $           i Nop)

  , (0x01, i1 $ \rp       -> i $ move (r4 $ fst4 rp) (r4 $ snd4 rp))
  , (0x02, i2 $ \rp w1    -> i $ move (r8 rp) (r16 w1))
  , (0x03, i3 $ \_  w1 w2 -> i $ move (r16 w1) (r16 w2))
  , (0x04, i1 $ \rp       -> i $ mwide (r4 $ fst4 rp) (r4 $ snd4 rp))
  , (0x05, i2 $ \rp w1    -> i $ mwide (r8 rp) (r16 w1))
  , (0x06, i3 $ \_  w1 w2 -> i $ mwide (r16 w1) (r16 w2))
  , (0x07, i1 $ \rp       -> i $ mobj (r4 $ fst4 rp) (r4 $ snd4 rp))
  , (0x08, i2 $ \rp w1    -> i $ mobj (r8 rp) (r16 w1))
  , (0x09, i3 $ \_  w1 w2 -> i $ mobj (r16 w1) (r16 w2))
  , (0x0a, i1 $ \rp       -> i $ mres (r8 rp))
  , (0x0b, i1 $ \rp       -> i $ mresw (r8 rp))
  , (0x0c, i1 $ \rp       -> i $ mreso (r8 rp))
  , (0x0d, i1 $ \rp       -> i $ movex (r8 rp))
  , (0x0e, noreg $           i ReturnVoid)
  , (0x0f, i1 $ \rp       -> i $ ret (r8 rp))
  , (0x10, i1 $ \rp       -> i $ retw (r8 rp))
  , (0x11, i1 $ \rp       -> i $ reto (r8 rp))
  -- TODO: const
  , (0x12, undefined)
  , (0x13, undefined)
  , (0x14, undefined)
  , (0x15, undefined)
  , (0x16, undefined)
  , (0x17, undefined)
  , (0x18, undefined)
  , (0x19, undefined)
  , (0x1a, undefined)
  , (0x1b, undefined)
  , (0x1c, undefined)
  , (0x1d, i1 $ \rp       -> i $ MonitorEnter rp)
  , (0x1e, i1 $ \rp       -> i $ MonitorExit rp)
  , (0x1f, i2 $ \rp w1    -> i $ CheckCast rp w1)
  , (0x20, i2 $ \rp w1    -> i $ InstanceOf (fst4 rp) (snd4 rp) w1)
  , (0x21, i1 $ \rp       -> i $ ArrayLength (fst4 rp) (snd4 rp))
  , (0x22, i2 $ \rp w1    -> i $ NewInstance rp w1)
  , (0x23, i2 $ \rp w1    -> i $ NewArray (fst4 rp) (snd4 rp) w1)

  , (0x24, undefined)
  , (0x25, undefined)
  , (0x26, undefined)

  , (0x27, i1 $ \rp       -> i $ Throw rp)

  , (0x28, i1 $ \rp       -> i $ Goto (fromIntegral rp))
  , (0x29, i2 $ \_  w1    -> i $ Goto (fromIntegral w1))
  , (0x2a, i3 $ \_  w1 w2 -> i $ Goto (combine16 w1 w2))

  , (0x2b, undefined)
  , (0x2c, undefined)

  , (0x2d, i2 $ \rp w1    -> i $ cmp CLFloat rp (fst8 w1) (snd8 w1))
  , (0x2e, i2 $ \rp w1    -> i $ cmp CGFloat rp (fst8 w1) (snd8 w1))
  , (0x2f, i2 $ \rp w1    -> i $ cmp CLDouble rp (fst8 w1) (snd8 w1))
  , (0x30, i2 $ \rp w1    -> i $ cmp CGDouble rp (fst8 w1) (snd8 w1))
  , (0x31, i2 $ \rp w1    -> i $ cmp CLong rp (fst8 w1) (snd8 w1))

  , (0x32, undefined)
  , (0x33, undefined)
  , (0x34, undefined)
  , (0x35, undefined)
  , (0x36, undefined)
  , (0x37, undefined)
  , (0x38, undefined)
  , (0x39, undefined)
  , (0x3a, undefined)
  , (0x3b, undefined)
  , (0x3c, undefined)
  , (0x3d, undefined)

  , (0x3e, noreg . fail . invalidOpcode $ 0x3e)
  , (0x3f, noreg . fail . invalidOpcode $ 0x3f)
  , (0x40, noreg . fail . invalidOpcode $ 0x40)
  , (0x41, noreg . fail . invalidOpcode $ 0x41)
  , (0x42, noreg . fail . invalidOpcode $ 0x42)
  , (0x43, noreg . fail . invalidOpcode $ 0x43)

  , (0x44, i2 $ \rp w1    -> i $ aget rp (fst8 w1) (snd8 w1))
  , (0x45, i2 $ \rp w1    -> i $ agetw rp (fst8 w1) (snd8 w1))
  , (0x46, i2 $ \rp w1    -> i $ ageto rp (fst8 w1) (snd8 w1))
  , (0x47, i2 $ \rp w1    -> i $ agetz rp (fst8 w1) (snd8 w1))
  , (0x48, i2 $ \rp w1    -> i $ agetb rp (fst8 w1) (snd8 w1))
  , (0x49, i2 $ \rp w1    -> i $ agetc rp (fst8 w1) (snd8 w1))
  , (0x4a, i2 $ \rp w1    -> i $ agets rp (fst8 w1) (snd8 w1))
  , (0x4b, i2 $ \rp w1    -> i $ aput rp (fst8 w1) (snd8 w1))
  , (0x4c, i2 $ \rp w1    -> i $ aputw rp (fst8 w1) (snd8 w1))
  , (0x4d, i2 $ \rp w1    -> i $ aputo rp (fst8 w1) (snd8 w1))
  , (0x4e, i2 $ \rp w1    -> i $ aputz rp (fst8 w1) (snd8 w1))
  , (0x4f, i2 $ \rp w1    -> i $ aputb rp (fst8 w1) (snd8 w1))
  , (0x50, i2 $ \rp w1    -> i $ aputc rp (fst8 w1) (snd8 w1))
  , (0x51, i2 $ \rp w1    -> i $ aputs rp (fst8 w1) (snd8 w1))

  , (0x52, i2 $ \rp w1    -> i $ iget (fst4 rp) (snd4 rp) w1)
  , (0x53, i2 $ \rp w1    -> i $ igetw (fst4 rp) (snd4 rp) w1)
  , (0x54, i2 $ \rp w1    -> i $ igeto (fst4 rp) (snd4 rp) w1)
  , (0x55, i2 $ \rp w1    -> i $ igetz (fst4 rp) (snd4 rp) w1)
  , (0x56, i2 $ \rp w1    -> i $ igetb (fst4 rp) (snd4 rp) w1)
  , (0x57, i2 $ \rp w1    -> i $ igetc (fst4 rp) (snd4 rp) w1)
  , (0x58, i2 $ \rp w1    -> i $ igets (fst4 rp) (snd4 rp) w1)
  , (0x59, i2 $ \rp w1    -> i $ iput (fst4 rp) (snd4 rp) w1)
  , (0x5a, i2 $ \rp w1    -> i $ iputw (fst4 rp) (snd4 rp) w1)
  , (0x5b, i2 $ \rp w1    -> i $ iputo (fst4 rp) (snd4 rp) w1)
  , (0x5c, i2 $ \rp w1    -> i $ iputz (fst4 rp) (snd4 rp) w1)
  , (0x5d, i2 $ \rp w1    -> i $ iputb (fst4 rp) (snd4 rp) w1)
  , (0x5e, i2 $ \rp w1    -> i $ iputc (fst4 rp) (snd4 rp) w1)
  , (0x5f, i2 $ \rp w1    -> i $ iputs (fst4 rp) (snd4 rp) w1)

  , (0x60, i2 $ \rp w1    -> i $ sget rp w1)
  , (0x61, i2 $ \rp w1    -> i $ sgetw rp w1)
  , (0x62, i2 $ \rp w1    -> i $ sgeto rp w1)
  , (0x63, i2 $ \rp w1    -> i $ sgetz rp w1)
  , (0x64, i2 $ \rp w1    -> i $ sgetb rp w1)
  , (0x65, i2 $ \rp w1    -> i $ sgetc rp w1)
  , (0x66, i2 $ \rp w1    -> i $ sgets rp w1)
  , (0x67, i2 $ \rp w1    -> i $ sput rp w1)
  , (0x68, i2 $ \rp w1    -> i $ sputw rp w1)
  , (0x69, i2 $ \rp w1    -> i $ sputo rp w1)
  , (0x6a, i2 $ \rp w1    -> i $ sputz rp w1)
  , (0x6b, i2 $ \rp w1    -> i $ sputb rp w1)
  , (0x6c, i2 $ \rp w1    -> i $ sputc rp w1)
  , (0x6d, i2 $ \rp w1    -> i $ sputs rp w1)
  ] ++
  map (\op -> (op, noreg . fail . invalidOpcode $ op)) [0x01..0xFF]
    where noreg = i1 . const
          i = return
          --f = fail
          i1 = IParse1
          i2 = IParse2
          i3 = IParse3
          --i5 = IParse5
          r4 = R4 . fromIntegral
          r8 = R8 . fromIntegral
          r16 = R16 . fromIntegral
          fst4 = fst . splitWord8
          snd4 = snd . splitWord8
          fst8 = fst . splitWord16
          snd8 = snd . splitWord16
          combine16 = undefined
          cmp = undefined

          move = Move MNormal
          mwide = Move MWide
          mobj = Move MObject
          mres = Move1 MResult
          mresw = Move1 MResultWide
          mreso = Move1 MResultObject
          movex = Move1 MException
          ret = Return MNormal
          retw = Return MWide
          reto = Return MObject

          aget = ArrayOp (Get Nothing)
          agetw = ArrayOp (Get (Just AWide))
          ageto = ArrayOp (Get (Just AObject))
          agetz = ArrayOp (Get (Just ABoolean))
          agetb = ArrayOp (Get (Just AByte))
          agetc = ArrayOp (Get (Just AChar))
          agets = ArrayOp (Get (Just AShort))
          aput = ArrayOp (Put Nothing)
          aputw = ArrayOp (Put (Just AWide))
          aputo = ArrayOp (Put (Just AObject))
          aputz = ArrayOp (Put (Just ABoolean))
          aputb = ArrayOp (Put (Just AByte))
          aputc = ArrayOp (Put (Just AChar))
          aputs = ArrayOp (Put (Just AShort))

          iget = InstanceFieldOp (Get Nothing)
          igetw = InstanceFieldOp (Get (Just AWide))
          igeto = InstanceFieldOp (Get (Just AObject))
          igetz = InstanceFieldOp (Get (Just ABoolean))
          igetb = InstanceFieldOp (Get (Just AByte))
          igetc = InstanceFieldOp (Get (Just AChar))
          igets = InstanceFieldOp (Get (Just AShort))
          iput = InstanceFieldOp (Put Nothing)
          iputw = InstanceFieldOp (Put (Just AWide))
          iputo = InstanceFieldOp (Put (Just AObject))
          iputz = InstanceFieldOp (Put (Just ABoolean))
          iputb = InstanceFieldOp (Put (Just AByte))
          iputc = InstanceFieldOp (Put (Just AChar))
          iputs = InstanceFieldOp (Put (Just AShort))

          sget = StaticFieldOp (Get Nothing)
          sgetw = StaticFieldOp (Get (Just AWide))
          sgeto = StaticFieldOp (Get (Just AObject))
          sgetz = StaticFieldOp (Get (Just ABoolean))
          sgetb = StaticFieldOp (Get (Just AByte))
          sgetc = StaticFieldOp (Get (Just AChar))
          sgets = StaticFieldOp (Get (Just AShort))
          sput = StaticFieldOp (Put Nothing)
          sputw = StaticFieldOp (Put (Just AWide))
          sputo = StaticFieldOp (Put (Just AObject))
          sputz = StaticFieldOp (Put (Just ABoolean))
          sputb = StaticFieldOp (Put (Just AByte))
          sputc = StaticFieldOp (Put (Just AChar))
          sputs = StaticFieldOp (Put (Just AShort))

iparser :: Word8 -> InsnParser
iparser = undefined

decodeInstructions :: [Word16] -> Either DecodeError [Instruction]
decodeInstructions [] = return []
decodeInstructions (w : ws) = case (iparser op, ws) of
  (IParse1 f,                       _) -> (:) <$> f rp             <*> go ws
  (IParse2 f, w1                : ws') -> (:) <$> f rp w1          <*> go ws'
  (IParse3 f, w1 : w2           : ws') -> (:) <$> f rp w1 w2       <*> go ws'
  (IParse5 f, w1 : w2 : w3 : w4 : ws') -> (:) <$> f rp w1 w2 w3 w4 <*> go ws'
  _ -> fail $ prematureEnd op
  where (rp, op) = splitWord16 w
        go = decodeInstructions

{-
encodeInstructions :: [Instruction] -> [Word16]
encodeInstructions = undefined
-}
