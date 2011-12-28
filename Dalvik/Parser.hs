module Dalvik.Parser where

import Control.Applicative
import Control.Monad
import Data.Bits
import qualified Data.ByteString as BS
import Data.Int
import qualified Data.Map as Map
import Data.Map (Map)
import Data.Serialize.Get
import Data.Word

import Debug.Trace

import Dalvik.Instruction

{-
Based on documentation from:
    http://netmite.com/android/mydroid/dalvik/docs/dex-format.htm
-}

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
type AccessFlags = Word32

data MapItem
  = MapItem {
      itemType :: Word16
    , itemSize :: Word32
    , itemOff  :: Word32
    } deriving (Show)

data StringDataItem = SDI Word32 [Word8]
  deriving (Show)

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
      protoDesc   :: StringId
    , protoRet    :: TypeId
    , protoParams :: ParamListId
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
    , classIntfsOff :: Word32
    , classSourceNameId :: StringId
    , classAnnotsOff :: Word32
    , classStaticFields :: [EncodedField]
    , classInstanceFields :: [EncodedField]
    , classDirectMethods :: [EncodedMethod]
    , classVirtualMethods :: [EncodedMethod]
    , classStaticValuesOff :: Word32
    } deriving (Show)

data TryItem
  = TryItem
    { tryStartAddr  :: Word32
    , tryInsnCount  :: Word16
    , tryHandlerOff :: Word16
    } deriving (Show)

data CodeItem
  = CodeItem
    { codeRegs      :: Word16
    , codeInSize    :: Word16
    , codeOutSize   :: Word16
    , codeDebugOff  :: Word32
    , codeInsns     :: [Word16] --[Instruction]
    {-
    , tryItems  :: [TryItem]
    , handlers  :: [CatchHandler]
    -}
    } deriving (Show)

showSDI :: StringDataItem -> String
showSDI (SDI _ str) = show (BS.pack str)

data DexFile =
  DexFile
  { dexHeader       :: DexHeader
  , dexStrings      :: Map StringId StringDataItem
  , dexTypes        :: [Word32]
  , dexProtos       :: Map ProtoId Proto
  , dexFields       :: Map FieldId Field
  , dexMethods      :: Map MethodId Method
  , dexClasses      :: Map TypeId Class
  } deriving (Show)

loadDexIO :: String -> IO (Either String DexFile)
loadDexIO f = loadDex <$> BS.readFile f

loadDex :: BS.ByteString -> Either String DexFile
loadDex bs = do
  h <- runGet parseDexHeader bs
  itemMap  <- doSection (dexMapOff h) 0 parseMap bs
  strings  <- doSection (dexOffStrings h) (dexNumStrings h) parseStrings bs
  types    <- doSection (dexOffTypes h) (dexNumTypes h) parseTypes bs
  protos   <- doSection (dexOffProtos h) (dexNumProtos h) parseProtos bs
  fields   <- doSection (dexOffFields h) (dexNumFields h) parseFields bs
  methods  <- doSection (dexOffMethods h) (dexNumMethods h) parseMethods bs
  classes  <- doSection (dexOffClassDefs h) (dexNumClassDefs h)
                        parseClassDefs bs
  {-
  ddata    <- doSection (dexDataOff h) (dexDataSize h) parseData bs
  linkInfo <- doSection (dexLinkOff h) (dexLinkSize h) parseLinkInfo bs
  -}
  return $ DexFile
           { dexHeader = h
           , dexStrings = strings
           , dexTypes = types
           , dexProtos = protos
           , dexFields = fields
           , dexMethods = methods
           , dexClasses = classes
           }

doSection :: Word32 -> Word32 -> (BS.ByteString -> Word32 -> Get a)
          -> BS.ByteString
          -> Either String a
doSection off size p bs =
  runGet (p bs size) $ BS.drop (fromIntegral off) bs

{- Header parsing -}

parseDexHeader :: Get DexHeader
parseDexHeader = do
  magic <- getBytes 4
  unless (magic == s "dex\n") $ fail "Invalid magic string"
  version <- getBytes 4
  unless (version == s "035\0") $ fail "Unsupported version"
  checksum <- getWord32le
  sha1 <- BS.unpack <$> getBytes 20
  fileLen <- getWord32le
  hdrLen <- getWord32le
  unless (hdrLen == 112) $ fail "Invalid header length"
  endianTag <- getWord32le
  -- TODO: support 0x78563412
  unless (endianTag == 0x12345678) $ fail "Unsupported endianness"
  linkSize <- getWord32le
  linkOff <- getWord32le
  mapOff <- getWord32le
  numStrings <- getWord32le
  offStrings <- getWord32le
  numTypes <- getWord32le
  offTypes <- getWord32le
  numProtos <- getWord32le
  offProtos <- getWord32le
  numFields <- getWord32le
  offFields <- getWord32le
  numMethods <- getWord32le
  offMethods <- getWord32le
  numClassDefs <- getWord32le
  offClassDefs <- getWord32le
  dataSize <- getWord32le
  dataOff <- getWord32le
  return $ DexHeader
           { dexMagic = magic
           , dexVersion = version
           , dexChecksum = checksum
           , dexSHA1 = sha1
           , dexFileLen = fileLen
           , dexHdrLen = hdrLen
           , dexLinkSize = linkSize
           , dexLinkOff = linkOff
           , dexMapOff = mapOff
           , dexNumStrings = numStrings
           , dexOffStrings = offStrings
           , dexNumTypes = numTypes
           , dexOffTypes = offTypes
           , dexNumProtos = numProtos
           , dexOffProtos = offProtos
           , dexNumFields = numFields
           , dexOffFields = offFields
           , dexNumMethods = numMethods
           , dexOffMethods = offMethods
           , dexNumClassDefs = numClassDefs
           , dexOffClassDefs = offClassDefs
           , dexDataSize = dataSize
           , dexDataOff = dataOff
           }

{- Section parsing -}

parseMap :: BS.ByteString -> Word32 -> Get (Map Word32 MapItem)
parseMap _ _ = do
  size <- getWord32le
  items <- replicateM (fromIntegral size) parseMapItem
  return . Map.fromList . zip [0..] $ items

parseMapItem :: Get MapItem
parseMapItem = do
  iType <- getWord16le
  unused <- getWord16le
  iSize <- getWord32le
  iOff <- getWord32le
  return $ MapItem iType iSize iOff

liftEither :: Either String a -> Get a
liftEither (Left err) = fail err
liftEither (Right a) = return a

subGet :: Integral c => BS.ByteString -> c -> Get a -> Get a
subGet bs off p = liftEither $ runGet p $ BS.drop (fromIntegral off) bs

parseStrings :: BS.ByteString -> Word32 -> Get (Map Word32 StringDataItem)
parseStrings bs size = do
  offs <- replicateM (fromIntegral size) getWord32le
  strs <- mapM (\off -> subGet bs off parseStringDataItem) offs
  return . Map.fromList . zip [0..] $ strs

parseStringDataItem :: Get StringDataItem
parseStringDataItem = do
  len <- getULEB128
  str <- getString
  return $ SDI len str

getString :: Get [Word8]
getString = do
  b <- getWord8
  if b == 0 then return [] else (b:) <$> getString

parseTypes :: BS.ByteString -> Word32 -> Get [Word32]
parseTypes bs size = replicateM (fromIntegral size) getWord32le

parseProtos :: BS.ByteString -> Word32 -> Get (Map ProtoId Proto)
parseProtos bs size = do
  protos <- replicateM (fromIntegral size) parseProto
  return . Map.fromList . zip [0..] $ protos

parseProto :: Get Proto
parseProto = do
  tyDescId <- getWord32le
  retTyId <- getWord32le
  paramListId <- getWord32le
  return $ Proto
           { protoDesc   = tyDescId
           , protoRet    = fromIntegral retTyId -- TODO: can this lose information?
           , protoParams = paramListId
           }

parseFields :: BS.ByteString -> Word32 -> Get (Map FieldId Field)
parseFields bs size = do
  fields <- replicateM (fromIntegral size) parseField
  return . Map.fromList . zip [0..] $ fields

parseField :: Get Field
parseField = Field <$> getWord16le <*> getWord16le <*> getWord32le

parseEncodedFields :: Word32 -> Maybe FieldId -> Get [EncodedField]
parseEncodedFields 0 _ = return []
parseEncodedFields n mprev = do
  efield <- parseEncodedField mprev
  efields <- parseEncodedFields (n - 1) (Just $ fieldId efield)
  return $ efield : efields

parseEncodedField :: Maybe FieldId -> Get EncodedField
parseEncodedField mprev = do
  fieldIdxDiff <- fromIntegral <$> getULEB128 -- TODO: data loss?
  let fieldIdx = maybe fieldIdxDiff (+ fieldIdxDiff) mprev
  accessFlags <- getULEB128
  return $ EncodedField
           { fieldId = fieldIdx
           , fieldAccessFlags = accessFlags
           }

parseMethods :: BS.ByteString -> Word32 -> Get (Map MethodId Method)
parseMethods bs size = do
  methods <- replicateM (fromIntegral size) parseMethod
  return . Map.fromList . zip [0..] $ methods

parseMethod :: Get Method
parseMethod = Method <$> getWord16le <*> getWord16le <*> getWord32le

parseEncodedMethods :: BS.ByteString -> Word32 -> Maybe MethodId
                    -> Get [EncodedMethod]
parseEncodedMethods bs 0 _ = return []
parseEncodedMethods bs n mprev = do
  emeth <- parseEncodedMethod bs mprev
  emeths <- parseEncodedMethods bs (n - 1) (Just $ methId emeth)
  return $ emeth : emeths

parseEncodedMethod :: BS.ByteString -> Maybe MethodId -> Get EncodedMethod
parseEncodedMethod bs mprev = do
  methIdxDiff <- fromIntegral <$> getULEB128 -- TODO: data loss?
  let methIdx = maybe methIdxDiff (+ methIdxDiff) mprev
  accessFlags <- getULEB128
  codeOffset <- getULEB128
  codeItem <- case codeOffset of
                0 -> return Nothing
                _ -> Just <$> subGet bs codeOffset parseCodeItem
  return $ EncodedMethod
           { methId = methIdx
           , methAccessFlags = accessFlags
           , methCode = codeItem
           }

parseCodeItem :: Get CodeItem
parseCodeItem = do
  regCount <- getWord16le
  inCount <- getWord16le
  outCount <- getWord16le
  tryCount <- getWord16le
  debugInfoOff <- getWord32le
  insnCount <- getWord32le
  insns <- replicateM (fromIntegral insnCount) getWord16le
  --_padding <- getWord16le
  -- TODO: parse tries
  -- TODO: parse handlers
  -- insns <- either fail return $ decodeInstructions insnWords
  return $ CodeItem
           { codeRegs = regCount
           , codeInSize = inCount
           , codeOutSize = outCount
           , codeDebugOff = debugInfoOff
           , codeInsns = insns
           }

parseClassDefs :: BS.ByteString -> Word32 -> Get (Map TypeId Class)
parseClassDefs bs size = do
  classes <- replicateM (fromIntegral size) (parseClassDef bs)
  return . Map.fromList . zip [0..] $ classes

parseClassDef :: BS.ByteString -> Get Class
parseClassDef bs = do
  classIdx        <- getWord32le
  accessFlags     <- getWord32le
  superclassId    <- getWord32le
  interfacesOff   <- getWord32le
  sourceNameId    <- getWord32le
  annotationsOff  <- getWord32le
  dataOff         <- getWord32le
  staticValuesOff <- getWord32le
  (staticFields, instanceFields,
   directMethods, virtualMethods) <- case dataOff of
                                       0 -> return ([], [], [], [])
                                       _ -> subGet bs dataOff (parseClassData bs)
  return $ Class
           { classId = fromIntegral classIdx -- TODO: can this lose information?
           , classAccessFlags = accessFlags
           , classSuperId = fromIntegral superclassId -- TODO: ditto
           , classIntfsOff = interfacesOff
           , classSourceNameId = sourceNameId
           , classAnnotsOff = annotationsOff
           , classStaticFields = staticFields
           , classInstanceFields = instanceFields
           , classDirectMethods = directMethods
           , classVirtualMethods = virtualMethods
           , classStaticValuesOff = staticValuesOff
           }

parseClassData :: BS.ByteString
               -> Get ( [EncodedField], [EncodedField]
                      , [EncodedMethod], [EncodedMethod] )
parseClassData bs = do
  staticFieldCount <- getULEB128
  instanceFieldCount <- getULEB128
  directMethodCount <- getULEB128
  virtualMethodCount <- getULEB128
  staticFields <- parseEncodedFields staticFieldCount Nothing
  instanceFields <- parseEncodedFields instanceFieldCount Nothing
  directMethods <- parseEncodedMethods bs directMethodCount Nothing
  virtualMethods <- parseEncodedMethods bs virtualMethodCount Nothing
  return (staticFields, instanceFields, directMethods, virtualMethods)

parseData :: BS.ByteString -> Word32 -> Get BS.ByteString
parseData bs size = getByteString (fromIntegral size)

parseLinkInfo :: BS.ByteString -> Word32 -> Get BS.ByteString
parseLinkInfo bs size = getByteString (fromIntegral size)

{- Utility functions -}

s :: String -> BS.ByteString
s = BS.pack . map toEnum . map fromEnum

{- Access Flags -}

data AccessFlag
  = ACC_PUBLIC
  | ACC_PRIVATE
  | ACC_PROTECTED
  | ACC_STATIC
  | ACC_FINAL
  | ACC_SYNCHRONIZED
  | ACC_VOLATILE
  | ACC_BRIDGE
  | ACC_TRANSIENT
  | ACC_VARARGS
  | ACC_NATIVE
  | ACC_INTERFACE
  | ACC_ABSTRACT
  | ACC_STRICT
  | ACC_SYNTHETIC
  | ACC_ANNOTATION
  | ACC_ENUM
  | ACC_CONSTRUCTOR
  | ACC_DECLARED_SYNCHRONIZED
    deriving (Enum, Eq, Ord, Show)

andTrue :: Word32 -> Word32 -> Bool
andTrue w1 w2 = (w1 .&. w2) /= 0

hasAccessFlag :: AccessFlag -> Word32 ->  Bool
hasAccessFlag ACC_PUBLIC = andTrue 0x00001
hasAccessFlag ACC_PRIVATE = andTrue 0x00002
hasAccessFlag ACC_PROTECTED = andTrue 0x00004
hasAccessFlag ACC_STATIC = andTrue 0x00008
hasAccessFlag ACC_FINAL = andTrue 0x00010
hasAccessFlag ACC_SYNCHRONIZED = andTrue 0x00020
hasAccessFlag ACC_VOLATILE = andTrue 0x00040
hasAccessFlag ACC_BRIDGE = andTrue 0x00040
hasAccessFlag ACC_TRANSIENT = andTrue 0x00080
hasAccessFlag ACC_VARARGS = andTrue 0x00080
hasAccessFlag ACC_NATIVE = andTrue 0x00100
hasAccessFlag ACC_INTERFACE = andTrue 0x00200
hasAccessFlag ACC_ABSTRACT = andTrue 0x00400
hasAccessFlag ACC_STRICT = andTrue 0x00800
hasAccessFlag ACC_SYNTHETIC = andTrue 0x01000
hasAccessFlag ACC_ANNOTATION = andTrue 0x02000
hasAccessFlag ACC_ENUM = andTrue 0x4000
hasAccessFlag ACC_CONSTRUCTOR = andTrue 0x10000
hasAccessFlag ACC_DECLARED_SYNCHRONIZED = andTrue 0x20000

{- LEB128 decoding -}

getSLEB128 :: Get Int32
getSLEB128 = do
  (a, n) <- smashLEB <$> getLEB
  let a' | a .&. (1 `shiftL` n) == 0 = a
         | otherwise = a .|. (0xFFFFFFFF `shiftL` n)
  return $ fromIntegral a'

getULEB128 :: Get Word32
getULEB128 = fst <$> smashLEB <$> getLEB

getULEB128p1 :: Get Int32
getULEB128p1 = (pred . fromIntegral) <$> getULEB128

smashLEB :: [Word8] -> (Word32, Int)
smashLEB = go 0 0
  where go a n [] = (a, n - 1)
        go a n (x : xs) = go ((x' `shiftL` n) .|. a) (n + 7) xs
          where x' = fromIntegral x

getLEB :: Get [Word8]
getLEB = do
  b <- getWord8
  ((b .&. 0x7F) :) <$> if (b .&. 0x80) /= 0 then getLEB else return []
