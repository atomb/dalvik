module Dalvik.Types where

import qualified Data.ByteString as BS
import qualified Data.Map as Map
import Data.Int
import Data.Map (Map)
import Data.Word

import Dalvik.AccessFlags

data DexHeader =
  DexHeader
  { dexMagic        :: BS.ByteString
  , dexVersion      :: BS.ByteString
  , dexChecksum     :: Word32
  , dexSHA1         :: [Word8]
  , dexFileLen      :: Word32
  , dexHdrLen       :: Word32
  , dexLinkSize     :: Word32
  , dexLinkOff      :: Word32
  , dexMapOff       :: Word32
  , dexNumStrings   :: Word32
  , dexOffStrings   :: Word32
  , dexNumTypes     :: Word32
  , dexOffTypes     :: Word32
  , dexNumProtos    :: Word32
  , dexOffProtos    :: Word32
  , dexNumFields    :: Word32
  , dexOffFields    :: Word32
  , dexNumMethods   :: Word32
  , dexOffMethods   :: Word32
  , dexNumClassDefs :: Word32
  , dexOffClassDefs :: Word32
  , dexDataSize     :: Word32
  , dexDataOff      :: Word32
  } deriving (Show)

type ProtoId = Word16
type ParamListId = Word32
type FieldId = Word16
type MethodId = Word16
type StringId = Word32
type StringIdJumbo = Word32
type TypeId = Word16

type Word4 = Word8

type Reg4 = Word4
type Reg8 = Word8
type Reg16 = Word16


data MapItem
  = MapItem {
      itemType :: Word16
    , itemSize :: Word32
    , itemOff  :: Word32
    } deriving (Show)

data Field
  = Field {
      fieldClassId :: TypeId
    , fieldTypeId  :: TypeId
    , fieldNameId  :: StringId
    } deriving (Show)

data EncodedField
  = EncodedField {
      fieldId :: FieldId
    , fieldAccessFlags :: AccessFlags
    } deriving (Show)

data Proto
  = Proto {
      protoShortDesc :: StringId
    , protoRet       :: TypeId
    , protoParams    :: [TypeId]
    } deriving (Show)

data Method
  = Method {
      methClassId  :: TypeId
    , methProtoId  :: ProtoId
    , methNameId   :: StringId
    } deriving (Show)

data EncodedMethod
  = EncodedMethod {
      methId :: MethodId
    , methAccessFlags :: AccessFlags
    , methCode :: Maybe CodeItem
    } deriving (Show)

data Class
  = Class
    { classId :: TypeId
    , classAccessFlags :: AccessFlags
    , classSuperId :: TypeId
    , classInterfacesOff :: Word32
    , classInterfaces :: [TypeId]
    , classSourceNameId :: StringId
    , classAnnotsOff :: Word32
    , classStaticFields :: [EncodedField]
    , classInstanceFields :: [EncodedField]
    , classDirectMethods :: [EncodedMethod]
    , classVirtualMethods :: [EncodedMethod]
    , classDataOff :: Word32
    , classStaticValuesOff :: Word32
    } deriving (Show)

data TryItem
  = TryItem
    { tryStartAddr  :: Word32
    , tryInsnCount  :: Word16
    , tryHandlerOff :: Word16
    } deriving (Show)

data CatchHandler
  = CatchHandler
    { chHandlerOff :: Word32
    , chHandlers   :: [(TypeId, Word32)]
    , chAllAddr    :: Maybe Word32
    } deriving (Show)

data CodeItem
  = CodeItem
    { codeRegs      :: Word16
    , codeInSize    :: Word16
    , codeOutSize   :: Word16
    , codeDebugInfo :: Maybe DebugInfo
    , codeInsnOff   :: Word32
    , codeInsns     :: [Word16]
    , codeTryItems  :: [TryItem]
    , codeHandlers  :: [CatchHandler]
    } deriving (Show)

data DexFile =
  DexFile
  { dexHeader       :: DexHeader
  , dexMap          :: Map Word32 MapItem
  , dexStrings      :: Map StringId BS.ByteString
  , dexTypeNames    :: Map TypeId StringId
  , dexProtos       :: Map ProtoId Proto
  , dexFields       :: Map FieldId Field
  , dexMethods      :: Map MethodId Method
  , dexClasses      :: Map TypeId Class
  , dexThisId       :: StringId
  } deriving (Show)

data DebugByteCode
  = DBG_END_SEQUENCE
  | DBG_ADVANCE_PC
  | DBG_ADVANCE_LINE
  | DBG_START_LOCAL
  | DBG_START_LOCAL_EXTENDED
  | DBG_END_LOCAL
  | DBG_RESTART_LOCAL
  | DBG_SET_PROLOGUE_END
  | DBG_SET_EPILOGUE_BEGIN
  | DBG_SET_FILE
  | DBG_FIRST_SPECIAL
    deriving (Eq, Enum)

data DebugInstruction
  = EndSequence
  | AdvancePC Word32
  | AdvanceLine Int32
  | StartLocal Word32 Int32 Int32 --(Maybe Word32) (Maybe Word32)
  | StartLocalExt Word32 Int32 Int32 Int32 --(Maybe Word32) (Maybe Word32) (Maybe Word32)
  | EndLocal Word32
  | RestartLocal Word32
  | SetPrologueEnd
  | SetEpilogueBegin
  | SetFile Int32 --(Maybe Word32)
  | SpecialAdjust Word8
    deriving (Show)

data DebugInfo
  = DebugInfo
    { dbgLineStart  :: Word32
    , dbgParamNames :: [Int32]
    , dbgByteCodes  :: [DebugInstruction]
    } deriving (Show)

data DebugState
  = DebugState
    { dbgAddr          :: Word32
    , dbgLine          :: Word32
    , dbgSourceFile    :: Int32
    , dbgPrologueEnd   :: Bool
    , dbgEpilogueBegin :: Bool
    , dbgLocals        :: Map Word32 [LocalInfo]
    , dbgPositions     :: [PositionInfo]
    , dbgSeqNo         :: Word32
    } deriving (Show)

data PositionInfo
  = PositionInfo
    { pAddr :: Word32
    , pLine :: Word32
    } deriving (Show)

data LocalInfo
  = LocalInfo
    { lSeqNo     :: Word32
    , lStartAddr :: Word32
    , lEndAddr   :: Word32
    , lNameID    :: Int32
    , lTypeID    :: Int32
    , lTypeSig   :: Int32
    } deriving (Eq, Ord, Show)

{- Utility functions -}

getStr :: DexFile -> StringId -> Maybe BS.ByteString
getStr dex i = Map.lookup i (dexStrings dex)

getTypeName :: DexFile -> TypeId -> Maybe BS.ByteString
getTypeName dex i =
  getStr dex =<< Map.lookup i (dexTypeNames dex)

getField :: DexFile -> FieldId -> Field
getField dex i = Map.findWithDefault (error msg) i (dexFields dex)
  where msg = "Unknown field ID " ++ show i

getMethod :: DexFile -> MethodId -> Method
getMethod dex i = Map.findWithDefault (error msg) i (dexMethods dex)
  where msg = "Unknown method ID " ++ show i

getProto :: DexFile -> ProtoId -> Proto
getProto dex i = Map.findWithDefault (error msg) i (dexProtos dex)
  where msg = "Unknown prototype ID " ++ show i

getClass :: DexFile -> TypeId -> Class
getClass dex i = Map.findWithDefault (error msg) i (dexClasses dex)
  where msg = "Unknown type ID " ++ show i

findString :: DexFile -> BS.ByteString -> StringId
findString dex t =
  case filter isThis (Map.toList (dexStrings dex)) of
    [(sid, _)] -> sid
    _ -> error $ "Can't find StringId of " ++ show t
  where isThis (_, t') = t == t'
