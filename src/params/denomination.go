// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package params

// These are the multipliers for SPX denominations, which help to represent
// different units of the SPX token in the Sphinx blockchain, similar to how
// currencies like Bitcoin and Ethereum use smaller units such as satoshis and wei.
// The base unit is nSPX (nano SPX), which is the smallest denomination, and
// larger units such as gSPX (giga SPX) and SPX (1 full token) are represented
// by multiplying nSPX values.

const (
	nSPX = 1e0  // 1 nSPX (nano SPX) is the smallest unit of SPX, similar to "wei" in Ethereum.
	gSPX = 1e9  // 1 gSPX (giga SPX) equals 1e9 nSPX. It's a larger denomination used for easier representation.
	SPX  = 1e18 // 1 SPX equals 1e18 nSPX, similar to how 1 Ether equals 1e18 wei.
)

// In the same way that 1 Ether = 1e18 wei, here:
// 1 SPX = 1e18 nSPX, and 1 gSPX = 1e9 nSPX.
//
// Example of conversions:
//
// To convert gSPX to nSPX, you can multiply the value in gSPX by gSPX multiplier:
// new(big.Int).Mul(valueInGSPX, big.NewInt(params.gSPX))
//
// To convert SPX to nSPX, multiply the value in SPX by the SPX multiplier:
// new(big.Int).Mul(valueInSPX, big.NewInt(params.SPX))
