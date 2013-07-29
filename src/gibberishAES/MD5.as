/**
 * @license Gibberish-AES (ActionScript 3 port)
 * 
 * Ported by Mikhail Vorobyov - https://github.com/NordMike
 * 
 * Original library - https://github.com/mdp/gibberish-aes
 * 
 * Original credits are below.
 *
 * A lightweight Javascript Libray for OpenSSL compatible AES CBC encryption.
 *
 * Author: Mark Percival
 * Email: mark@mpercival.com
 * Copyright: Mark Percival - http://mpercival.com 2008
 *
 * With thanks to:
 * Josh Davis - http://www.josh-davis.org/ecmaScrypt
 * Chris Veness - http://www.movable-type.co.uk/scripts/aes.html
 * Michel I. Gallant - http://www.jensign.com/
 * Jean-Luc Cooke <jlcooke@certainkey.com> 2012-07-12: added strhex + invertArr to compress G2X/G3X/G9X/GBX/GEX/SBox/SBoxInv/Rcon saving over 7KB, and added encString, decString, also made the MD5 routine more easlier compressible using yuicompressor.
 *
 * License: MIT
 */

package gibberishAES {
	
	/**
	 * ...
	 * @author
	 */
	public class MD5 {
		
		public function MD5() {
			throw new Error("Static class.");
		}
		
		private static function rotateLeft(lValue:int, iShiftBits:int):int {
			return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
		}
		
		private static function addUnsigned(lX:int, lY:int):int {
			var lX4:int;
			var lY4:int;
			var lX8:int;
			var lY8:int;
			var lResult:int;
			lX8 = (lX & 0x80000000);
			lY8 = (lY & 0x80000000);
			lX4 = (lX & 0x40000000);
			lY4 = (lY & 0x40000000);
			lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
			if (lX4 & lY4) {
				return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
			}
			if (lX4 | lY4) {
				if (lResult & 0x40000000) {
					return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
				} else {
					return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
				}
			} else {
				return (lResult ^ lX8 ^ lY8);
			}
		}
		
		private static function f(x:int, y:int, z:int):int {
			return (x & y) | ((~x) & z);
		}
		
		private static function g(x:int, y:int, z:int):int {
			return (x & z) | (y & (~z));
		}
		
		private static function h(x:int, y:int, z:int):int {
			return (x ^ y ^ z);
		}
		
		private static function funcI(x:int, y:int, z:int):int {
			return (y ^ (x | (~z)));
		}
		
		private static function ff(a:int, b:int, c:int, d:int, x:int, s:int, ac:int):int {
			a = addUnsigned(a, addUnsigned(addUnsigned(f(b, c, d), x), ac));
			return addUnsigned(rotateLeft(a, s), b);
		}
		
		private static function gg(a:int, b:int, c:int, d:int, x:int, s:int, ac:int):int {
			a = addUnsigned(a, addUnsigned(addUnsigned(g(b, c, d), x), ac));
			return addUnsigned(rotateLeft(a, s), b);
		}
		
		private static function hh(a:int, b:int, c:int, d:int, x:int, s:int, ac:int):int {
			a = addUnsigned(a, addUnsigned(addUnsigned(h(b, c, d), x), ac));
			return addUnsigned(rotateLeft(a, s), b);
		}
		
		private static function ii(a:int, b:int, c:int, d:int, x:int, s:int, ac:int):int {
			a = addUnsigned(a, addUnsigned(addUnsigned(funcI(b, c, d), x), ac));
			return addUnsigned(rotateLeft(a, s), b);
		}
		
		private static function convertToWordArray(numArr:Array):Array {
			var lWordCount:int;
			var lMessageLength:int = numArr.length;
			var lNumberOfWords_temp1:int = lMessageLength + 8;
			var lNumberOfWords_temp2:int = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
			var lNumberOfWords:int = (lNumberOfWords_temp2 + 1) * 16;
			var lWordArray:Array = new Array();
			var lBytePosition:int = 0;
			var lByteCount:int = 0;
			while (lByteCount < lMessageLength) {
				lWordCount = (lByteCount - (lByteCount % 4)) / 4;
				lBytePosition = (lByteCount % 4) * 8;
				lWordArray[lWordCount] = (lWordArray[lWordCount] | (numArr[lByteCount] << lBytePosition));
				lByteCount++;
			}
			lWordCount = (lByteCount - (lByteCount % 4)) / 4;
			lBytePosition = (lByteCount % 4) * 8;
			lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
			lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
			lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
			return lWordArray;
		}
		
		private static function wordToHex(lValue:int):Array {
			var lByte:int;
			var lCount:int;
			var wordToHexArr:Array = new Array();
			for (lCount = 0; lCount <= 3; lCount++) {
				lByte = (lValue >>> (lCount * 8)) & 255;
				wordToHexArr = wordToHexArr.concat(lByte);
			}
			return wordToHexArr;
		}
		
		public static function encode(numArr:Array):Array {
			var x:Array = new Array();
			var k:int;
			var AA:int;
			var BB:int;
			var CC:int;
			var DD:int;
			var a:int;
			var b:int;
			var c:int;
			var d:int;
			var rnd:Array = Util.strhex('67452301efcdab8998badcfe10325476d76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501698098d88b44f7afffff5bb1895cd7be6b901122fd987193a679438e49b40821f61e2562c040b340265e5a51e9b6c7aad62f105d02441453d8a1e681e7d3fbc821e1cde6c33707d6f4d50d87455a14eda9e3e905fcefa3f8676f02d98d2a4c8afffa39428771f6816d9d6122fde5380ca4beea444bdecfa9f6bb4b60bebfbc70289b7ec6eaa127fad4ef308504881d05d9d4d039e6db99e51fa27cf8c4ac5665f4292244432aff97ab9423a7fc93a039655b59c38f0ccc92ffeff47d85845dd16fa87e4ffe2ce6e0a30143144e0811a1f7537e82bd3af2352ad7d2bbeb86d391', 8);
			
			x = convertToWordArray(numArr);
			
			a = rnd[0];
			b = rnd[1];
			c = rnd[2];
			d = rnd[3];
			
			for (k = 0; k < x.length; k += 16) {
				AA = a;
				BB = b;
				CC = c;
				DD = d;
				a = ff(a, b, c, d, x[k + 0], 7, rnd[4]);
				d = ff(d, a, b, c, x[k + 1], 12, rnd[5]);
				c = ff(c, d, a, b, x[k + 2], 17, rnd[6]);
				b = ff(b, c, d, a, x[k + 3], 22, rnd[7]);
				a = ff(a, b, c, d, x[k + 4], 7, rnd[8]);
				d = ff(d, a, b, c, x[k + 5], 12, rnd[9]);
				c = ff(c, d, a, b, x[k + 6], 17, rnd[10]);
				b = ff(b, c, d, a, x[k + 7], 22, rnd[11]);
				a = ff(a, b, c, d, x[k + 8], 7, rnd[12]);
				d = ff(d, a, b, c, x[k + 9], 12, rnd[13]);
				c = ff(c, d, a, b, x[k + 10], 17, rnd[14]);
				b = ff(b, c, d, a, x[k + 11], 22, rnd[15]);
				a = ff(a, b, c, d, x[k + 12], 7, rnd[16]);
				d = ff(d, a, b, c, x[k + 13], 12, rnd[17]);
				c = ff(c, d, a, b, x[k + 14], 17, rnd[18]);
				b = ff(b, c, d, a, x[k + 15], 22, rnd[19]);
				a = gg(a, b, c, d, x[k + 1], 5, rnd[20]);
				d = gg(d, a, b, c, x[k + 6], 9, rnd[21]);
				c = gg(c, d, a, b, x[k + 11], 14, rnd[22]);
				b = gg(b, c, d, a, x[k + 0], 20, rnd[23]);
				a = gg(a, b, c, d, x[k + 5], 5, rnd[24]);
				d = gg(d, a, b, c, x[k + 10], 9, rnd[25]);
				c = gg(c, d, a, b, x[k + 15], 14, rnd[26]);
				b = gg(b, c, d, a, x[k + 4], 20, rnd[27]);
				a = gg(a, b, c, d, x[k + 9], 5, rnd[28]);
				d = gg(d, a, b, c, x[k + 14], 9, rnd[29]);
				c = gg(c, d, a, b, x[k + 3], 14, rnd[30]);
				b = gg(b, c, d, a, x[k + 8], 20, rnd[31]);
				a = gg(a, b, c, d, x[k + 13], 5, rnd[32]);
				d = gg(d, a, b, c, x[k + 2], 9, rnd[33]);
				c = gg(c, d, a, b, x[k + 7], 14, rnd[34]);
				b = gg(b, c, d, a, x[k + 12], 20, rnd[35]);
				a = hh(a, b, c, d, x[k + 5], 4, rnd[36]);
				d = hh(d, a, b, c, x[k + 8], 11, rnd[37]);
				c = hh(c, d, a, b, x[k + 11], 16, rnd[38]);
				b = hh(b, c, d, a, x[k + 14], 23, rnd[39]);
				a = hh(a, b, c, d, x[k + 1], 4, rnd[40]);
				d = hh(d, a, b, c, x[k + 4], 11, rnd[41]);
				c = hh(c, d, a, b, x[k + 7], 16, rnd[42]);
				b = hh(b, c, d, a, x[k + 10], 23, rnd[43]);
				a = hh(a, b, c, d, x[k + 13], 4, rnd[44]);
				d = hh(d, a, b, c, x[k + 0], 11, rnd[45]);
				c = hh(c, d, a, b, x[k + 3], 16, rnd[46]);
				b = hh(b, c, d, a, x[k + 6], 23, rnd[47]);
				a = hh(a, b, c, d, x[k + 9], 4, rnd[48]);
				d = hh(d, a, b, c, x[k + 12], 11, rnd[49]);
				c = hh(c, d, a, b, x[k + 15], 16, rnd[50]);
				b = hh(b, c, d, a, x[k + 2], 23, rnd[51]);
				a = ii(a, b, c, d, x[k + 0], 6, rnd[52]);
				d = ii(d, a, b, c, x[k + 7], 10, rnd[53]);
				c = ii(c, d, a, b, x[k + 14], 15, rnd[54]);
				b = ii(b, c, d, a, x[k + 5], 21, rnd[55]);
				a = ii(a, b, c, d, x[k + 12], 6, rnd[56]);
				d = ii(d, a, b, c, x[k + 3], 10, rnd[57]);
				c = ii(c, d, a, b, x[k + 10], 15, rnd[58]);
				b = ii(b, c, d, a, x[k + 1], 21, rnd[59]);
				a = ii(a, b, c, d, x[k + 8], 6, rnd[60]);
				d = ii(d, a, b, c, x[k + 15], 10, rnd[61]);
				c = ii(c, d, a, b, x[k + 6], 15, rnd[62]);
				b = ii(b, c, d, a, x[k + 13], 21, rnd[63]);
				a = ii(a, b, c, d, x[k + 4], 6, rnd[64]);
				d = ii(d, a, b, c, x[k + 11], 10, rnd[65]);
				c = ii(c, d, a, b, x[k + 2], 15, rnd[66]);
				b = ii(b, c, d, a, x[k + 9], 21, rnd[67]);
				a = addUnsigned(a, AA);
				b = addUnsigned(b, BB);
				c = addUnsigned(c, CC);
				d = addUnsigned(d, DD);
			}
			
			return wordToHex(a).concat(wordToHex(b), wordToHex(c), wordToHex(d));
		}
	}

}