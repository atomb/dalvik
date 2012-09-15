{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE MagicHash #-}

module Dalvik.HexPrint where

import Data.Bits
import Data.Monoid
import Data.Text.Lazy.Builder
import Data.Word
import GHC.Base

-- | Unsafe conversion for decimal digits.
i2d :: Int -> Char
i2d (I# i#) = C# (chr# (ord# '0'# +# i#))
{-# INLINE i2d #-}

hexDigit :: Integral a => a -> Builder
hexDigit n
    | n <= 9    = singleton $! i2d (fromIntegral n)
    | otherwise = singleton $! toEnum (fromIntegral n + 87)
{-# INLINE hexDigit #-}

fixedHex :: (Integral a, Bits a) => Int -> a -> Builder
fixedHex digits i = go digits i
  where
    go 0 _ = mempty
    go 1 n = hexDigit (n .&. 0xF)
    go d n = hexDigit ((n .&. mask) `shiftR` shiftAmt) `mappend`
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

