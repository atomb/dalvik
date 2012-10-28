{-# LANGUAGE OverloadedStrings #-}
module Dalvik.Parser
  ( loadDexIO
  , loadDex
  ) where

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8()
import qualified Data.Map as Map
import Data.Map (Map)
import Data.Serialize.Get
import Data.Word

import Dalvik.LEB128
import Dalvik.Types

{-
Based on documentation from:
    http://netmite.com/android/mydroid/dalvik/docs/dex-format.htm
-}

loadDexIO :: FilePath -> IO (Either String DexFile)
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
  let dex = DexFile
            { dexHeader = h
            , dexMap = itemMap
            , dexStrings = strings
            , dexTypeNames = types
            , dexProtos = protos
            , dexFields = fields
            , dexMethods = methods
            , dexClasses = classes
            , dexThisId = maybe (-1) id $ findString dex "this"
            }
  return dex

currDexOffset :: DexHeader -> Get Word32
currDexOffset hdr =
  (dexFileLen hdr -) <$> (fromIntegral `fmap` remaining)

doSection :: Word32 -> Word32 -> (BS.ByteString -> Word32 -> Get a)
          -> BS.ByteString
          -> Either String a
doSection off size p bs =
  runGet (p bs size) $ BS.drop (fromIntegral off) bs

{- Header parsing -}

parseDexHeader :: Get DexHeader
parseDexHeader = do
  magic <- getByteString 4
  unless (magic == "dex\n") $ fail "Invalid magic string"
  version <- getByteString 4
  unless (version == "035\0") $ fail "Unsupported version"
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
  return DexHeader
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

parseStrings :: BS.ByteString -> Word32 -> Get (Map Word32 BS.ByteString)
parseStrings bs size = do
  offs <- replicateM (fromIntegral size) getWord32le
  strs <- mapM (\off -> subGet bs off parseStringDataItem) offs
  return . Map.fromList . zip [0..] $ strs

parseStringDataItem :: Get BS.ByteString
parseStringDataItem = getULEB128 >>=  const (BS.pack <$> go)
  where go = do c <- getWord8
                if c == 0 then return [] else (c:) <$> go

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
  return Proto
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
  return EncodedField
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
  codeItem <- subGet' bs codeOffset Nothing (Just <$> parseCodeItem hdr bs)
  return EncodedMethod
           { methId = methIdx
           , methAccessFlags = accessFlags
           , methCode = codeItem
           }

parseCodeItem :: DexHeader -> BS.ByteString -> Get CodeItem
parseCodeItem hdr bs = do
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
  debugInfo <- subGet' bs debugInfoOff Nothing (Just <$> parseDebugInfo)
  -- insns <- either fail return $ decodeInstructions insnWords
  return CodeItem
           { codeRegs = regCount
           , codeInSize = inCount
           , codeOutSize = outCount
           , codeDebugInfo = debugInfo
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

parseDebugInfo :: Get DebugInfo
parseDebugInfo = do
  lineStart <- getULEB128
  paramCount <- getULEB128
  paramNames <- replicateM (fromIntegral paramCount) getULEB128p1
  byteCodes <- parseByteCodes
  return $ DebugInfo lineStart paramNames byteCodes

parseByteCodes :: Get [DebugInstruction]
parseByteCodes = do
  bc <- getWord8
  insn <- parseByteCode bc
  case insn of
    EndSequence -> return []
    _ -> (insn :) <$> parseByteCodes

parseByteCode :: Word8 -> Get DebugInstruction
parseByteCode bc
  | fromIntegral bc < fromEnum DBG_FIRST_SPECIAL =
    case toEnum (fromIntegral bc) of
      DBG_END_SEQUENCE -> return EndSequence
      DBG_ADVANCE_PC -> AdvancePC <$> getULEB128
      DBG_ADVANCE_LINE -> AdvanceLine <$> getSLEB128
      DBG_START_LOCAL ->
        StartLocal <$> getULEB128 <*> getULEB128p1 <*> getULEB128p1
      DBG_START_LOCAL_EXTENDED ->
        StartLocalExt <$> getULEB128 <*> getULEB128p1
                      <*> getULEB128p1 <*> getULEB128p1
      DBG_END_LOCAL -> EndLocal <$> getULEB128
      DBG_RESTART_LOCAL -> RestartLocal <$> getULEB128
      DBG_SET_PROLOGUE_END -> return SetPrologueEnd
      DBG_SET_EPILOGUE_BEGIN -> return SetEpilogueBegin
      DBG_SET_FILE -> SetFile <$> getULEB128p1
      _ -> fail "internal: invalid debug byte code"
  | otherwise = return (SpecialAdjust bc)

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
  return Class
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

{-
parseData :: BS.ByteString -> Word32 -> Get BS.ByteString
parseData _ size = getByteString (fromIntegral size)

parseLinkInfo :: BS.ByteString -> Word32 -> Get BS.ByteString
parseLinkInfo _ size = getByteString (fromIntegral size)
-}

