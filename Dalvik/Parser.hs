module Dalvik.Parser where

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.Map as Map
import Data.Map (Map)
import Data.Serialize.Get
import Data.Word

import Dalvik.AccessFlags
import Dalvik.Instruction
import Dalvik.LEB128

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
    , codeDebugOff  :: Word32
    , codeInsnOff   :: Word32
    , codeInsns     :: [Word16]
    , codeTryItems  :: [TryItem]
    , codeHandlers  :: [CatchHandler]
    } deriving (Show)

showSDI :: StringDataItem -> String
showSDI (SDI _ s) = show (BS.pack s)

data DexFile =
  DexFile
  { dexHeader       :: DexHeader
  , dexMap          :: Map Word32 MapItem
  , dexStrings      :: Map StringId StringDataItem
  , dexTypeNames    :: Map TypeId StringId
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
                        (parseClassDefs h) bs
  {-
  ddata    <- doSection (dexDataOff h) (dexDataSize h) parseData bs
  linkInfo <- doSection (dexLinkOff h) (dexLinkSize h) parseLinkInfo bs
  -}
  return $ DexFile
           { dexHeader = h
           , dexMap = itemMap
           , dexStrings = strings
           , dexTypeNames = types
           , dexProtos = protos
           , dexFields = fields
           , dexMethods = methods
           , dexClasses = classes
           }

currDexOffset :: DexHeader -> Get Word32
currDexOffset hdr =
  ((dexFileLen hdr) -) <$> (fromIntegral `fmap` remaining)

doSection :: Word32 -> Word32 -> (BS.ByteString -> Word32 -> Get a)
          -> BS.ByteString
          -> Either String a
doSection off size p bs =
  runGet (p bs size) $ BS.drop (fromIntegral off) bs

{- Header parsing -}

parseDexHeader :: Get DexHeader
parseDexHeader = do
  magic <- getBytes 4
  unless (magic == str "dex\n") $ fail "Invalid magic string"
  version <- getBytes 4
  unless (version == str "035\0") $ fail "Unsupported version"
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
  _unused <- getWord16le
  iSize <- getWord32le
  iOff <- getWord32le
  return $ MapItem iType iSize iOff

liftEither :: Either String a -> Get a
liftEither (Left err) = fail err
liftEither (Right a) = return a

subGet :: Integral c => BS.ByteString -> c -> Get a -> Get a
subGet bs off p = liftEither $ runGet p $ BS.drop (fromIntegral off) bs

subGet' :: Integral c => BS.ByteString -> c -> a -> Get a -> Get a
subGet' _ 0 def _ = return def
subGet' bs off _ p = subGet bs off p

parseStrings :: BS.ByteString -> Word32 -> Get (Map Word32 StringDataItem)
parseStrings bs size = do
  offs <- replicateM (fromIntegral size) getWord32le
  strs <- mapM (\off -> subGet bs off parseStringDataItem) offs
  return . Map.fromList . zip [0..] $ strs

parseStringDataItem :: Get StringDataItem
parseStringDataItem = SDI <$> getULEB128 <*> getString

getString :: Get [Word8]
getString = do
  b <- getWord8
  if b == 0 then return [] else (b:) <$> getString

parseTypes :: BS.ByteString -> Word32 -> Get (Map TypeId StringId)
parseTypes _ size =
  (Map.fromList . zip [0..]) <$> replicateM (fromIntegral size) getWord32le

parseTypeList :: Get [TypeId]
parseTypeList = do
  size <- getWord32le
  replicateM (fromIntegral size) getWord16le

parseProtos :: BS.ByteString -> Word32 -> Get (Map ProtoId Proto)
parseProtos bs size = do
  protos <- replicateM (fromIntegral size) (parseProto bs)
  return . Map.fromList . zip [0..] $ protos

parseProto :: BS.ByteString -> Get Proto
parseProto bs = do
  tyDescId <- getWord32le
  retTyId <- getWord32le
  paramListOff <- getWord32le
  params <- subGet' bs paramListOff [] parseTypeList
  return $ Proto
           { protoShortDesc = tyDescId
           -- TODO: can the following lose information?
           , protoRet       = fromIntegral retTyId
           , protoParams    = params
           }

parseFields :: BS.ByteString -> Word32 -> Get (Map FieldId Field)
parseFields _ size = do
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
parseMethods _ size = do
  methods <- replicateM (fromIntegral size) parseMethod
  return . Map.fromList . zip [0..] $ methods

parseMethod :: Get Method
parseMethod = Method <$> getWord16le <*> getWord16le <*> getWord32le

parseEncodedMethods :: DexHeader -> BS.ByteString -> Word32 -> Maybe MethodId
                    -> Get [EncodedMethod]
parseEncodedMethods _ _ 0 _ = return []
parseEncodedMethods hdr bs n mprev = do
  emeth <- parseEncodedMethod hdr bs mprev
  emeths <- parseEncodedMethods hdr bs (n - 1) (Just $ methId emeth)
  return $ emeth : emeths

parseEncodedMethod :: DexHeader -> BS.ByteString -> Maybe MethodId
                   -> Get EncodedMethod
parseEncodedMethod hdr bs mprev = do
  methIdxDiff <- fromIntegral <$> getULEB128 -- TODO: data loss?
  let methIdx = maybe methIdxDiff (+ methIdxDiff) mprev
  accessFlags <- getULEB128
  codeOffset <- getULEB128
  codeItem <- subGet' bs codeOffset Nothing (Just <$> parseCodeItem hdr)
  return $ EncodedMethod
           { methId = methIdx
           , methAccessFlags = accessFlags
           , methCode = codeItem
           }

parseCodeItem :: DexHeader -> Get CodeItem
parseCodeItem hdr = do
  regCount <- getWord16le
  inCount <- getWord16le
  outCount <- getWord16le
  tryCount <- getWord16le
  debugInfoOff <- getWord32le
  insnCount <- getWord32le
  insnOff <- currDexOffset hdr
  insns <- replicateM (fromIntegral insnCount) getWord16le
  _ <- if tryCount > 0 && odd insnCount then getWord16le else return 0
  tryItems <- replicateM (fromIntegral tryCount) parseTryItem
  r <- remaining
  handlers <-
    if tryCount == 0 then return []
    else
      do handlerSize <- getULEB128
         replicateM (fromIntegral handlerSize) (parseEncodedCatchHandler r)
  -- insns <- either fail return $ decodeInstructions insnWords
  return $ CodeItem
           { codeRegs = regCount
           , codeInSize = inCount
           , codeOutSize = outCount
           , codeDebugOff = debugInfoOff
           , codeInsnOff = insnOff
           , codeInsns = insns
           , codeTryItems = tryItems
           , codeHandlers = handlers
           }

parseTryItem :: Get TryItem
parseTryItem = TryItem <$> getWord32le <*> getWord16le <*> getWord16le

parseEncodedCatchHandler :: Int -> Get CatchHandler
parseEncodedCatchHandler startRem = do
  r <- remaining
  handlerSize <- getSLEB128
  handlers <- replicateM (abs (fromIntegral handlerSize))
              parseEncodedTypeAddrPair
  catchAllAddr <- if handlerSize <= 0
                  then Just <$> getULEB128
                  else return Nothing
  let off = fromIntegral $ startRem - r
  return $ CatchHandler off handlers catchAllAddr

parseEncodedTypeAddrPair :: Get (TypeId, Word32)
parseEncodedTypeAddrPair =
  (,) <$> (fromIntegral `fmap` getULEB128) <*> getULEB128

parseClassDefs :: DexHeader -> BS.ByteString -> Word32
               -> Get (Map TypeId Class)
parseClassDefs hdr bs size =
  Map.fromList . zip [0..] <$>
  replicateM (fromIntegral size) (parseClassDef hdr bs)

parseClassDef :: DexHeader -> BS.ByteString -> Get Class
parseClassDef hdr bs = do
  classIdx        <- getWord32le
  accessFlags     <- getWord32le
  superclassId    <- getWord32le
  interfacesOff   <- getWord32le
  ifaces          <- subGet' bs interfacesOff [] parseTypeList
  sourceNameId    <- getWord32le
  annotationsOff  <- getWord32le
  dataOff         <- getWord32le
  staticValuesOff <- getWord32le
  (staticFields, instanceFields,
   directMethods, virtualMethods) <-
      subGet' bs dataOff ([], [], [], []) (parseClassData hdr bs)
  return $ Class
           { classId = fromIntegral classIdx -- TODO: can this lose information?
           , classAccessFlags = accessFlags
           , classSuperId = fromIntegral superclassId -- TODO: ditto
           , classInterfacesOff = interfacesOff
           , classInterfaces = ifaces
           , classSourceNameId = sourceNameId
           , classAnnotsOff = annotationsOff
           , classStaticFields = staticFields
           , classInstanceFields = instanceFields
           , classDirectMethods = directMethods
           , classVirtualMethods = virtualMethods
           , classDataOff = dataOff
           , classStaticValuesOff = staticValuesOff
           }

parseClassData :: DexHeader -> BS.ByteString
               -> Get ( [EncodedField], [EncodedField]
                      , [EncodedMethod], [EncodedMethod] )
parseClassData hdr bs = do
  staticFieldCount <- getULEB128
  instanceFieldCount <- getULEB128
  directMethodCount <- getULEB128
  virtualMethodCount <- getULEB128
  staticFields <- parseEncodedFields staticFieldCount Nothing
  instanceFields <- parseEncodedFields instanceFieldCount Nothing
  directMethods <- parseEncodedMethods hdr bs directMethodCount Nothing
  virtualMethods <- parseEncodedMethods hdr bs virtualMethodCount Nothing
  return (staticFields, instanceFields, directMethods, virtualMethods)

parseData :: BS.ByteString -> Word32 -> Get BS.ByteString
parseData _ size = getByteString (fromIntegral size)

parseLinkInfo :: BS.ByteString -> Word32 -> Get BS.ByteString
parseLinkInfo _ size = getByteString (fromIntegral size)

{- Utility functions -}

str :: String -> BS.ByteString
str = BS.pack . map toEnum . map fromEnum

getStr :: DexFile -> StringId -> StringDataItem
getStr dex i = Map.findWithDefault (error msg) i (dexStrings dex)
  where msg = "Unknown string ID " ++ show i

getTypeName :: DexFile -> TypeId -> StringDataItem
getTypeName dex i =
  getStr dex (Map.findWithDefault (error msg) i (dexTypeNames dex))
    where msg = "Uknown type ID " ++ show i

getField :: DexFile -> FieldId -> Field
getField dex i = Map.findWithDefault (error msg) i (dexFields dex)
  where msg = "Unknown field ID " ++ show i

getMethod :: DexFile -> MethodId -> Method
getMethod dex i = Map.findWithDefault (error msg) i (dexMethods dex)
  where msg = "Unknown method ID " ++ show i

getProto :: DexFile -> ProtoId -> Proto
getProto dex i = Map.findWithDefault (error msg) i (dexProtos dex)
  where msg = "Unknown prototype ID " ++ show i

