module Dalvik.Instruction where

import Control.Applicative
import Control.Monad.Instances
import Data.Array
import Data.Bits
import Data.Int
import Data.Word

type FieldId = Word16
type MethodId = Word16
type StringId = Word32
type StringIdJumbo = Word32
type TypeId = Word16
type ClassId = Word16
type ProtoId = Word16
type AccessFlags = Word32

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
  | ConstString StringId
  | ConstStringJumbo StringId
  | ConstClass TypeId

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

data IfOp
  = Eq
  | Ne
  | Lt
  | Ge
  | Gt
  | Le

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
  | LoadConst Reg ConstArg
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
  | PackedSwitch Reg8 Word32
  | SparseSwitch Reg8 Word32
  | Cmp CmpOp Reg8 Reg8 Reg8
  | If IfOp Reg4 Reg4 Int16
  | IfZero IfOp Reg8 Int16
  | ArrayOp AccessOp Reg8 Reg8 Reg8
  | InstanceFieldOp AccessOp Reg4 Reg4 FieldId
  | StaticFieldOp AccessOp Reg8 FieldId
  -- TODO: how best to encode invoke instructions?
  | Invoke InvokeKind MethodId [Word16]
  | Unop Unop Reg4 Reg4
  | IBinop Binop Bool Reg8 Reg8 Reg8
  | FBinop Binop Bool Reg8 Reg8 Reg8
  | IBinopAssign Binop Bool Reg4 Reg4
  | FBinopAssign Binop Bool Reg4 Reg4
  | BinopLit16 Binop Reg4 Reg4 Int16
  | BinopLit8 Binop Reg8 Reg8 Int8

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
  = IParse1 IParseResult
  | IParse2 (Word16 -> IParseResult)
  | IParse3 (Word16 -> Word16 -> IParseResult)
  | IParse5 (Word16 -> Word16 -> Word16 -> Word16 -> IParseResult)

-- TODO: check that ignored rps are zero?
iparseTable :: Array Word8 (Word8 -> InsnParser)
iparseTable = array (0x00, 0xFF) $
  [ (0x00, noreg     $           i Nop)
  -- Move
  , (0x01, \rp -> i1 $           i $ move (r4 $ fst4 rp) (r4 $ snd4 rp))
  , (0x02, \rp -> i2 $ \w1    -> i $ move (r8 rp) (r16 w1))
  , (0x03, \_  -> i3 $ \w1 w2 -> i $ move (r16 w1) (r16 w2))
  , (0x04, \rp -> i1 $           i $ mwide (r4 $ fst4 rp) (r4 $ snd4 rp))
  , (0x05, \rp -> i2 $ \w1    -> i $ mwide (r8 rp) (r16 w1))
  , (0x06, \_  -> i3 $ \w1 w2 -> i $ mwide (r16 w1) (r16 w2))
  , (0x07, \rp -> i1 $           i $ mobj (r4 $ fst4 rp) (r4 $ snd4 rp))
  , (0x08, \rp -> i2 $ \w1    -> i $ mobj (r8 rp) (r16 w1))
  , (0x09, \_  -> i3 $ \w1 w2 -> i $ mobj (r16 w1) (r16 w2))
  , (0x0a, \rp -> i1 $           i $ mres (r8 rp))
  , (0x0b, \rp -> i1 $           i $ mresw (r8 rp))
  , (0x0c, \rp -> i1 $           i $ mreso (r8 rp))
  , (0x0d, \rp -> i1 $           i $ movex (r8 rp))
  -- Return
  , (0x0e, noreg     $           i ReturnVoid)
  , (0x0f, \rp -> i1 $           i $ ret (r8 rp))
  , (0x10, \rp -> i1 $           i $ retw (r8 rp))
  , (0x11, \rp -> i1 $           i $ reto (r8 rp))
  -- Constants
  , (0x12, \rp -> i1 $           i $
     LoadConst (r4 $ fst4 rp) (Const4 . fromIntegral . snd4 $ rp))
  , (0x13, \rp -> i2 $ \w1    -> i $
     LoadConst (r8 rp) (Const16 (fromIntegral w1)))
  , (0x14, \rp -> i3 $ \w1 w2 -> i $
     LoadConst (r8 rp) (Const32 (combine16 w1 w2)))
  , (0x15, \rp -> i2 $ \w1    -> i $
     LoadConst (r8 rp) (ConstHigh16 (fromIntegral w1)))
  , (0x16, \rp -> i2 $ \w1    -> i $
     LoadConst (r8 rp) (ConstWide16 (fromIntegral w1)))
  , (0x17, \rp -> i3 $ \w1 w2 -> i $
     LoadConst (r8 rp) (ConstWide32 (combine16 w1 w2)))
  , (0x18, \rp -> i5 $ \w1 w2 w3 w4 -> i $
     LoadConst (r8 rp) (ConstWide (combine16' w1 w2 w3 w4)))
  , (0x19, \rp -> i2 $ \w1    -> i $
     LoadConst (r8 rp) (ConstWideHigh16 (fromIntegral w1)))
  , (0x1a, \rp -> i2 $ \w1    -> i $ LoadConst (r8 rp) (ConstString (fromIntegral w1)))
  , (0x1b, \rp -> i3 $ \w1 w2 -> i $
     LoadConst (r8 rp) (ConstStringJumbo (combine16 w1 w2)))
  , (0x1c, \rp -> i2 $ \w1    -> i $ LoadConst (r8 rp) (ConstClass w1))
  -- Monitors
  , (0x1d, \rp -> i1 $           i $ MonitorEnter rp)
  , (0x1e, \rp -> i1 $           i $ MonitorExit rp)
  -- Casting
  , (0x1f, \rp -> i2 $ \w1    -> i $ CheckCast rp w1)
  , (0x20, \rp -> i2 $ \w1    -> i $ InstanceOf (fst4 rp) (snd4 rp) w1)
  -- Arrays
  , (0x21, \rp -> i1 $           i $ ArrayLength (fst4 rp) (snd4 rp))
  , (0x22, \rp -> i2 $ \w1    -> i $ NewInstance rp w1)
  , (0x23, \rp -> i2 $ \w1    -> i $ NewArray (fst4 rp) (snd4 rp) w1)
  , (0x24, undefined)
  , (0x25, undefined)
  , (0x26, undefined)
  -- Exceptions
  , (0x27, \rp -> i1 $           i $ Throw rp)
  -- Unconditional branches
  , (0x28, \rp -> i1 $           i $ Goto (fromIntegral rp))
  , (0x29, \_  -> i2 $ \w1    -> i $ Goto (fromIntegral w1))
  , (0x2a, \_  -> i3 $ \w1 w2 -> i $ Goto (combine16 w1 w2))
  -- Switch
  , (0x2b, \rp -> i3 $ \w1 w2 -> i $ PackedSwitch rp (combine16 w1 w2))
  , (0x2c, \rp -> i3 $ \w1 w2 -> i $ SparseSwitch rp (combine16 w1 w2))
  -- Comparisons
  , (0x2d, cmp CLFloat)
  , (0x2e, cmp CGFloat)
  , (0x2f, cmp CLDouble)
  , (0x30, cmp CGDouble)
  , (0x31, cmp CLong)
  -- If comparisons
  , (0x32, ifop Eq)
  , (0x33, ifop Ne)
  , (0x34, ifop Lt)
  , (0x35, ifop Ge)
  , (0x36, ifop Gt)
  , (0x37, ifop Le)
  -- If comparisons with zero
  , (0x38, ifzop Eq)
  , (0x39, ifzop Ne)
  , (0x3a, ifzop Lt)
  , (0x3b, ifzop Ge)
  , (0x3c, ifzop Gt)
  , (0x3d, ifzop Le)
  -- Unused
  , invalid 0x3e
  , invalid 0x3f
  , invalid 0x40
  , invalid 0x41
  , invalid 0x42
  , invalid 0x43
  -- Array operations
  , (0x44, arrop (Get Nothing))
  , (0x45, arrop (Get (Just AWide)))
  , (0x46, arrop (Get (Just AObject)))
  , (0x47, arrop (Get (Just ABoolean)))
  , (0x48, arrop (Get (Just AByte)))
  , (0x49, arrop (Get (Just AChar)))
  , (0x4a, arrop (Get (Just AShort)))
  , (0x4b, arrop (Put Nothing))
  , (0x4c, arrop (Put (Just AWide)))
  , (0x4d, arrop (Put (Just AObject)))
  , (0x4e, arrop (Put (Just ABoolean)))
  , (0x4f, arrop (Put (Just AByte)))
  , (0x50, arrop (Put (Just AChar)))
  , (0x51, arrop (Put (Just AShort)))
  -- Instance field operations
  , (0x52, instop (Get Nothing))
  , (0x53, instop (Get (Just AWide)))
  , (0x54, instop (Get (Just AObject)))
  , (0x55, instop (Get (Just ABoolean)))
  , (0x56, instop (Get (Just AByte)))
  , (0x57, instop (Get (Just AChar)))
  , (0x58, instop (Get (Just AShort)))
  , (0x59, instop (Put Nothing))
  , (0x5a, instop (Put (Just AWide)))
  , (0x5b, instop (Put (Just AObject)))
  , (0x5c, instop (Put (Just ABoolean)))
  , (0x5d, instop (Put (Just AByte)))
  , (0x5e, instop (Put (Just AChar)))
  , (0x5f, instop (Put (Just AShort)))
  -- Static field operations
  , (0x60, statop (Get Nothing))
  , (0x61, statop (Get (Just AWide)))
  , (0x62, statop (Get (Just AObject)))
  , (0x63, statop (Get (Just ABoolean)))
  , (0x64, statop (Get (Just AByte)))
  , (0x65, statop (Get (Just AChar)))
  , (0x66, statop (Get (Just AShort)))
  , (0x67, statop (Put Nothing))
  , (0x68, statop (Put (Just AWide)))
  , (0x69, statop (Put (Just AObject)))
  , (0x6a, statop (Put (Just ABoolean)))
  , (0x6b, statop (Put (Just AByte)))
  , (0x6c, statop (Put (Just AChar)))
  , (0x6d, statop (Put (Just AShort)))
  -- Invoke with fixed argument counts
  , (0x6e, invoke Virtual)
  , (0x6f, invoke Super)
  , (0x70, invoke Direct)
  , (0x71, invoke Static)
  , (0x72, invoke Interface)
  -- Unused
  , invalid 0x73
  -- Invoke with arbitrary argument counts
  , (0x74, invokeRange Virtual)
  , (0x75, invokeRange Super)
  , (0x76, invokeRange Direct)
  , (0x77, invokeRange Static)
  , (0x78, invokeRange Interface)
  -- Unused
  , invalid 0x79
  , invalid 0x7a
  -- Unary operators
  , (0x7b, unop NegInt)
  , (0x7c, unop NotInt)
  , (0x7d, unop NegLong)
  , (0x7e, unop NotLong)
  , (0x7f, unop NegFloat)
  , (0x80, unop NegDouble)
  , (0x81, unop (Convert Int Long))
  , (0x82, unop (Convert Int Float))
  , (0x83, unop (Convert Int Double))
  , (0x84, unop (Convert Long Int))
  , (0x85, unop (Convert Long Float))
  , (0x86, unop (Convert Long Double))
  , (0x87, unop (Convert Float Int))
  , (0x88, unop (Convert Float Long))
  , (0x89, unop (Convert Float Double))
  , (0x8a, unop (Convert Double Int))
  , (0x8b, unop (Convert Double Long))
  , (0x8c, unop (Convert Double Float))
  , (0x8d, unop (Convert Int Byte))
  , (0x8e, unop (Convert Int Char))
  , (0x8f, unop (Convert Int Short))
  -- Binary operators
  , (0x90, ibinop Add)
  , (0x91, ibinop Sub)
  , (0x92, ibinop Mul)
  , (0x93, ibinop Div)
  , (0x94, ibinop Rem)
  , (0x95, ibinop And)
  , (0x96, ibinop Or)
  , (0x97, ibinop Xor)
  , (0x98, ibinop Shl)
  , (0x99, ibinop Shr)
  , (0x9a, ibinop UShr)
  , (0x9b, lbinop Add)
  , (0x9c, lbinop Sub)
  , (0x9d, lbinop Mul)
  , (0x9e, lbinop Div)
  , (0x9f, lbinop Rem)
  , (0xa0, lbinop And)
  , (0xa1, lbinop Or)
  , (0xa2, lbinop Xor)
  , (0xa3, lbinop Shl)
  , (0xa4, lbinop Shr)
  , (0xa5, lbinop UShr)
  , (0xa6, fbinop Add)
  , (0xa7, fbinop Sub)
  , (0xa8, fbinop Mul)
  , (0xa9, fbinop Div)
  , (0xaa, fbinop Rem)
  , (0xab, dbinop Add)
  , (0xac, dbinop Sub)
  , (0xad, dbinop Mul)
  , (0xae, dbinop Div)
  , (0xaf, dbinop Rem)
  -- Binary assignment operators
  , (0xb0, ibinopa Add)
  , (0xb1, ibinopa Sub)
  , (0xb2, ibinopa Mul)
  , (0xb3, ibinopa Div)
  , (0xb4, ibinopa Rem)
  , (0xb5, ibinopa And)
  , (0xb6, ibinopa Or)
  , (0xb7, ibinopa Xor)
  , (0xb8, ibinopa Shl)
  , (0xb9, ibinopa Shr)
  , (0xba, ibinopa UShr)
  , (0xbb, lbinopa Add)
  , (0xbc, lbinopa Sub)
  , (0xbd, lbinopa Mul)
  , (0xbe, lbinopa Div)
  , (0xbf, lbinopa Rem)
  , (0xc0, lbinopa And)
  , (0xc1, lbinopa Or)
  , (0xc2, lbinopa Xor)
  , (0xc3, lbinopa Shl)
  , (0xc4, lbinopa Shr)
  , (0xc5, lbinopa UShr)
  , (0xc6, fbinopa Add)
  , (0xc7, fbinopa Sub)
  , (0xc8, fbinopa Mul)
  , (0xc9, fbinopa Div)
  , (0xca, fbinopa Rem)
  , (0xcb, dbinopa Add)
  , (0xcc, dbinopa Sub)
  , (0xcd, dbinopa Mul)
  , (0xce, dbinopa Div)
  , (0xcf, dbinopa Rem)
  -- Binary operators with 16-bit literal arguments
  , (0xd0, binopl16 Add)
  , (0xd1, binopl16 RSub)
  , (0xd2, binopl16 Mul)
  , (0xd3, binopl16 Div)
  , (0xd4, binopl16 Rem)
  , (0xd5, binopl16 And)
  , (0xd6, binopl16 Or)
  , (0xd7, binopl16 Xor)
  -- Binary operators with 8-bit literal arguments
  , (0xd8, binopl8 Add)
  , (0xd9, binopl8 RSub)
  , (0xda, binopl8 Mul)
  , (0xdb, binopl8 Div)
  , (0xdc, binopl8 Rem)
  , (0xdd, binopl8 And)
  , (0xde, binopl8 Or)
  , (0xdf, binopl8 Xor)
  , (0xe0, binopl8 Shl)
  , (0xe1, binopl8 Shr)
  , (0xe2, binopl8 UShr)
  -- Unused
  , invalid 0xe3
  , invalid 0xe4
  , invalid 0xe5
  , invalid 0xe6
  , invalid 0xe7
  , invalid 0xe8
  , invalid 0xe9
  , invalid 0xea
  , invalid 0xeb
  , invalid 0xec
  , invalid 0xed
  , invalid 0xee
  , invalid 0xef
  , invalid 0xf0
  , invalid 0xf1
  , invalid 0xf2
  , invalid 0xf3
  , invalid 0xf4
  , invalid 0xf5
  , invalid 0xf6
  , invalid 0xf7
  , invalid 0xf8
  , invalid 0xf9
  , invalid 0xfa
  , invalid 0xfb
  , invalid 0xfc
  , invalid 0xfd
  , invalid 0xfe
  , invalid 0xff
  ] where noreg = const . i1
          i = return
          i1 = IParse1
          i2 = IParse2
          i3 = IParse3
          i5 = IParse5
          r4 = R4 . fromIntegral
          r8 = R8 . fromIntegral
          r16 = R16 . fromIntegral
          fst4 = fst . splitWord8
          snd4 = snd . splitWord8
          fst8 = fst . splitWord16
          snd8 = snd . splitWord16
          combine16 w1 w2 = (fromIntegral w1 `shiftL` 16) .|. fromIntegral w2
          combine16' w1 w2 w3 w4 =
            (fromIntegral w1 `shiftL` 32) .|.
            (fromIntegral w2 `shiftL` 24) .|.
            (fromIntegral w3 `shiftL` 16) .|.
            fromIntegral w4
          cmp op rp = i2 $ \w1 -> i $ Cmp op rp (fst8 w1) (snd8 w1)
          ifop op rp =
            i2 $ \w1 -> i $ If op (fst4 rp) (snd4 rp) (fromIntegral w1)
          ifzop op rp = i2 $ \w1 -> i $ IfZero op rp (fromIntegral w1)
          unop op rp = i1 $ i $ Unop op (fst4 rp) (snd4 rp)
          arrop op rp = i2 $ \w1 -> i $ ArrayOp op rp (fst8 w1) (snd8 w1)
          instop op rp =
            i2 $ \w1 -> i $ InstanceFieldOp op (fst4 rp) (snd4 rp) w1
          statop op rp = i2 $ \w1 -> i $ StaticFieldOp op rp w1
          invoke ty rp =
            i3 $ \w1 w2 ->
              let (b, a) = splitWord8 rp
                  g = fst4 $ fst8 w2
                  f = snd4 $ fst8 w2
                  e = fst4 $ snd8 w2
                  d = snd4 $ snd8 w2
                  inv args = i $ Invoke ty w1 $ map fromIntegral args
              in
              case b of
                0 -> inv []
                1 -> inv [d]
                2 -> inv [d, e]
                3 -> inv [d, e, f]
                4 -> inv [d, e, f, g]
                5 -> inv [d, e, f, g, a]
                _ -> fail $ "Invalid number of arguments: " ++ show b
          invokeRange ty rp = undefined
          binop c w op rp = i2 $ \w1 -> i $ c op w rp (fst8 w1) (snd8 w1)
          binopa c w op rp = i1 $ i $ c op w (fst4 rp) (snd4 rp)
          ibinop = binop IBinop False
          lbinop = binop IBinop True
          fbinop = binop FBinop False
          dbinop = binop FBinop True
          ibinopa = binopa IBinopAssign False
          lbinopa = binopa IBinopAssign True
          fbinopa = binopa FBinopAssign False
          dbinopa = binopa FBinopAssign True
          binopl16 op rp = i2 $ \w1 ->
            i $ BinopLit16 op (fst4 rp) (snd4 rp) (fromIntegral w1)
          binopl8 op rp = i2 $ \w1 ->
            i $ BinopLit8 op rp (fst8 w1) (fromIntegral $ snd8 w1)
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
          invalid op = (op, noreg . fail . invalidOpcode $ op)

iparser :: Word8 -> Word8 -> InsnParser
iparser = (!) iparseTable

decodeInstructions :: [Word16] -> Either DecodeError [Instruction]
decodeInstructions [] = return []
decodeInstructions (w : ws) = case (iparser op rp, ws) of
  (IParse1 f,                       _) -> (:) <$> f             <*> go ws
  (IParse2 f, w1                : ws') -> (:) <$> f w1          <*> go ws'
  (IParse3 f, w1 : w2           : ws') -> (:) <$> f w1 w2       <*> go ws'
  (IParse5 f, w1 : w2 : w3 : w4 : ws') -> (:) <$> f w1 w2 w3 w4 <*> go ws'
  _ -> fail $ prematureEnd op
  where (rp, op) = splitWord16 w
        go = decodeInstructions

{-
encodeInstructions :: [Instruction] -> [Word16]
encodeInstructions = undefined
-}
