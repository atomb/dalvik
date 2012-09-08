{-# LANGUAGE ParallelListComp #-}
module Dalvik.DebugInfo where

import Data.Int
import Data.List
import Data.Map (Map, alter, empty, findWithDefault, insertWith)
import qualified Data.Map as Map
import Data.Word

import Dalvik.AccessFlags
import Dalvik.Instruction
import Dalvik.Types

import Debug.Trace

initialDebugState :: DebugInfo -> Int32 -> DebugState
initialDebugState info srcFile =
  DebugState
  { dbgAddr          = 0
  , dbgLine          = dbgLineStart info
  , dbgSourceFile    = srcFile
  , dbgPrologueEnd   = False
  , dbgEpilogueBegin = False
  , dbgLocals        = empty
  , dbgPositions     = []
  }

dbgLineBase, dbgLineRange :: Word32
dbgLineBase = -4
dbgLineRange = 15

startLocal :: DebugState -> Word32 -> Int32 -> Int32 -> Int32
           -> DebugState
startLocal s r nid tid sid =
  s { dbgLocals =
        insertWith (++) r [LocalInfo a 0xFFFFFFFF nid tid sid] (dbgLocals s) }
    where a = dbgAddr s

endLocal :: DebugState -> Word32 -> DebugState
endLocal s r = s { dbgLocals = alter fixupEnd r (dbgLocals s) }
  where fixupEnd (Just (LocalInfo a _ nid tid sid : ls)) =
          Just $ LocalInfo a (dbgAddr s) nid tid sid : ls
        fixupEnd _ =
          --trace ("endLocal: " ++ show r ++ " " ++ " " ++ show s) $
          Just [LocalInfo 0 (dbgAddr s) (-1) (-1) (-1)]

restartLocal :: DebugState -> Word32 -> DebugState
restartLocal s r =
  case findWithDefault [] r (dbgLocals s) of
    (LocalInfo _ _ nid tid sid : _) -> startLocal s r nid tid sid
    [] -> --trace ("restartLocal: " ++ show r) $
          startLocal s r (-1) (-1) (-1)

executeInsn :: DebugState -> DebugInstruction -> DebugState
executeInsn s i =
  --trace (show s) $
  --trace (show i) $
  case i of
    EndSequence -> s
    AdvancePC off -> s { dbgAddr = dbgAddr s + off }
    AdvanceLine off -> s { dbgLine = dbgLine s + fromIntegral off }
    StartLocal r nid tid -> startLocal s r nid tid (-1)
    StartLocalExt r nid tid sid -> startLocal s r nid tid sid
    EndLocal r -> endLocal s r
    RestartLocal r -> restartLocal s r
    SetPrologueEnd -> s { dbgPrologueEnd = True }
    SetEpilogueBegin -> s { dbgEpilogueBegin = True }
    SetFile sid -> s { dbgSourceFile = sid }
    SpecialAdjust op -> s { dbgAddr = addr'
                          , dbgLine = line'
                          , dbgPrologueEnd = False
                          , dbgEpilogueBegin = False
                          , dbgPositions = p : dbgPositions s
                          }
      where adjOpcode = fromIntegral $
                        fromIntegral op - fromEnum DBG_FIRST_SPECIAL
            line' = dbgLine s + dbgLineBase + (adjOpcode `mod` dbgLineRange) -- - 4
            addr' = dbgAddr s + (adjOpcode `div` dbgLineRange)
            p = PositionInfo addr' line'

executeInsns :: CodeItem -> AccessFlags -> [TypeId] -> Word32 -> Int32
             -> DebugState
executeInsns code flags paramTypes lastAddr srcFile = -- trace (show info) $
  finishLocals lastAddr $
  foldl' executeInsn (initialDebugState info srcFile) is
    where is = [ StartLocal r nid (fromIntegral tid)
                   | r <- [paramStartReg..]
                   | tid <- ptypes
                   | nid <- pnames ] ++ dbgByteCodes info
          info = codeDebugInfo code
          hasThis = not $ hasAccessFlag ACC_STATIC flags
          paramStartReg = fromIntegral (codeRegs code) - fromIntegral (length pnames)
          pnames = (if hasThis then (thisId :) else id) (dbgParamNames info)
          ptypes = (if hasThis then (thisTid :) else id) paramTypes
          thisTid = (-1) -- TODO: what is the TypeId of 'this'
          thisId = (-1) -- TODO: what is the StringId of 'this'

finishLocals :: Word32 -> DebugState -> DebugState
finishLocals lastAddr s = s { dbgLocals = Map.map updLocal (dbgLocals s) }
  where updLocal (LocalInfo s 0xFFFFFFFF nid tid sid : ls) =
          LocalInfo s (lastAddr + 1) nid tid sid : ls
        updLocal ls = ls
