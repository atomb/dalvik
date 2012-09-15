{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE MagicHash #-}

module Dalvik.HexPrint where

import Data.Bits
import Data.Monoid
import Blaze.ByteString.Builder
import Data.Word

hexDigit :: Integral a => a -> Word8
hexDigit n
    | n <= 9    = fromIntegral n + 48
    | otherwise = fromIntegral n + 87
{-# INLINE hexDigit #-}

hexadecimal :: Integral a => a -> Builder
hexadecimal i
    | i < 0     = error msg
    | otherwise = fromWrite $ go i
  where
    go n | n < 16    = writeWord8 $! hexDigit n
         | otherwise = go (n `quot` 16) `mappend` (writeWord8 $! hexDigit (n `rem` 16))
    msg = "Dalvik.HexPrint.hexadecimal: applied to negative number"
{-# INLINE hexadecimal #-}

fixedHex :: (Integral a, Bits a) => Int -> a -> Builder
fixedHex digits i = fromWrite $ go digits i
  where
    go 0 _ = mempty
    go 1 n = writeWord8 $! hexDigit (n .&. 0xF)
    go d n = (writeWord8 $! hexDigit ((n .&. mask) `shiftR` shiftAmt)) `mappend`
             go (d - 1) n
               where mask = 0xF `shiftL` shiftAmt
                     shiftAmt = (d - 1) * 4
{-# INLINE fixedHex #-}

h2 :: Word8 -> Builder
h2 = fixedHex 2
{-# INLINE h2 #-}

h4 :: Word16 -> Builder
h4 = fixedHex 4
{-# INLINE h4 #-}

h5, h6, h8 :: Word32 -> Builder
h5 = fixedHex 5
h6 = fixedHex 6
h8 = fixedHex 8
{-# INLINE h5 #-}
{-# INLINE h6 #-}
{-# INLINE h8 #-}

h16 :: Word64 -> Builder
h16 = fixedHex 16
{-# INLINE h16 #-}

