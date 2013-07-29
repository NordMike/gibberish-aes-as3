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
	import adobe.utils.CustomActions;
	import flash.utils.ByteArray;
	
	public class AESCrypter {
		
		public function AESCrypter() {
			throw new Error("Static class.");
		}
		
		private static var Nr:int = 14;
		/* Default to 256 Bit Encryption */
		private static var Nk:int = 8;
		
		/**
		 * State of crypter, decryption or encryption.
		 * @default flase
		 */
		public static var Decrypt:Boolean = false;
		
		private static function enc_utf8(s:String):String {
			try {
				return unescape(encodeURIComponent(s));
			} catch (e:Error) {
				throw 'Error on UTF-8 encode';
			}
			return '';
		}
		
		private static function dec_utf8(s:String):String {
			try {
				return decodeURIComponent(escape(s));
			} catch (e:Error) {
				throw('Bad Key');
			}
			return '';
		}
		
		private static function padBlock(byteArr:Array):Array {
			var array:Array;
			var cpad:int;
			var i:int;
			if (byteArr.length < 16) {
				cpad = 16 - byteArr.length;
				array = new Array(cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad,
								  cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad);
			} else
				array = new Array();
			for (i = 0; i < byteArr.length; i++) {
				array[i] = byteArr[i];
			}
			return array;
		}
		
		private static function block2s(block:Array, lastBlock:Boolean):String {
			var string:String = new String();
			var padding:int;
			var i:int;
			if (lastBlock) {
				padding = block[15];
				if (padding > 16) {
					throw('Decryption error: Maybe bad key');
				}
				if (padding === 16) {
					return '';
				}
				for (i = 0; i < 16 - padding; i++) {
					string += String.fromCharCode(block[i]);
				}
			} else {
				for (i = 0; i < 16; i++) {
					string += String.fromCharCode(block[i]);
				}
			}
			return string;
		}
		
		/**
		 * Converts byte array to string of hexademical numbers.
		 * @param	numArr
		 * @return string of hexademical numbers.
		 */
		public static function a2h(numArr:Array):String {
			var string:String = new String();
			var i:int;
			for (i = 0; i < numArr.length; i++) {
				string += (numArr[i] < 16 ? '0' : '') + numArr[i].toString(16);
			}
			return string;
		}
		
		/**
		 * Converts String of hexademical numbers to Array of int.
		 * @param	s string of hexademical numbers representing byte array.
		 * @return array of int.
		 */
		public static function h2a(s:String):Array {
			var result:Array = new Array();
			s.replace(/(..)/g, function(... rest):String {
					result.push(parseInt(rest[0], 16));
					return rest[0];
				});
			return result;
		}
		
		/**
		 * Convert String of text to Array of int.
		 * @param	string text.
		 * @param	binary if binary is true string will be procesed by endoceURIComponent.
		 * @return array of int.
		 */
		public static function s2a(string:String, binary:Boolean = false):Array {
			var array:Array = new Array();
			var i:int;
			
			if (!binary) {
				string = enc_utf8(string);
			}
			
			for (i = 0; i < string.length; i++) {
				array[i] = string.charCodeAt(i);
			}
			
			return array;
		}
		/**
		 * Sets size of cypher key.
		 * @param	newsize size of key to be set.
		 */
		public static function size(newsize:int):void {
			switch (newsize) {
				case 128: 
					Nr = 10;
					Nk = 4;
					break;
				case 192: 
					Nr = 12;
					Nk = 6;
					break;
				case 256: 
					Nr = 14;
					Nk = 8;
					break;
				default: 
					throw('Invalid Key Size Specified:' + newsize);
			}
		}
		
		private static function randArr(num:int):Array {
			var result:Array = new Array();
			var i:int;
			for (i = 0; i < num; i++) {
				result.push(Math.floor(Math.random() * 256));
			}
			return result;
		}
		
		/**
		 * Produces OpenSSL key.
		 * @param	passwordArr
		 * @param	saltArr
		 * @return OpenSSL key. Object {key, iv}.
		 */
		public static function openSSLKey(passwordArr:Array, saltArr:Array):Object {
			// Number of rounds depends on the size of the AES in use
			// 3 rounds for 256
			// 2 rounds for the key, 1 for the IV
			// 2 rounds for 128
			// 1 round for the key, 1 round for the IV
			// 3 rounds for 192 since it's not evenly divided by 128 bits
			var rounds:int = Nr >= 12 ? 3 : 2;
			var key:Array;
			var iv:Array;
			var md5_hash:Array = new Array();
			var result:Array;
			var data00:Array = passwordArr.concat(saltArr);
			var i:int;
			
			md5_hash[0] = MD5.encode(data00);
			result = md5_hash[0];
			for (i = 1; i < rounds; i++) {
				md5_hash[i] = MD5.encode(md5_hash[i - 1].concat(data00));
				result = result.concat(md5_hash[i]);
			}
			key = result.slice(0, 4 * Nk);
			iv = result.slice(4 * Nk, 4 * Nk + 16);
			return {key: key, iv: iv};
		}
		
		/**
		 * Encrypt array of bytes.
		 * @param	plaintext
		 * @param	key
		 * @param	iv
		 * @return encrypted array.
		 */
		public static function rawEncrypt(plaintext:Array, key:Array, iv:Array):Array {
			// plaintext, key and iv as byte arrays
			key = expandKey(key);
			var numBlocks:int = Math.ceil(plaintext.length / 16);
			var blocks:Array = new Array();
			var i:int;
			var cipherBlocks:Array = new Array();
			for (i = 0; i < numBlocks; i++) {
				blocks[i] = padBlock(plaintext.slice(i * 16, i * 16 + 16));
			}
			if (plaintext.length % 16 === 0) {
				blocks.push(new Array(16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16));
				// CBC OpenSSL padding scheme
				numBlocks++;
			}
			for (i = 0; i < blocks.length; i++) {
				blocks[i] = (i === 0) ? xorBlocks(blocks[i], iv) : xorBlocks(blocks[i], cipherBlocks[i - 1]);
				cipherBlocks[i] = encryptBlock(blocks[i], key);
			}
			return cipherBlocks;
		}
		
		/**
		 * Decrypt array of bytes.
		 * @param	cryptArr
		 * @param	key
		 * @param	iv
		 * @param	binary
		 * @return derrypted array.
		 */
		public static function rawDecrypt(cryptArr:Array, key:Array, iv:Array, binary:Boolean = false):String {
			// cryptArr, key and iv as byte arrays
			key = expandKey(key);
			var numBlocks:int = cryptArr.length / 16;
			var cipherBlocks:Array = new Array();
			var i:int;
			var plainBlocks:Array = new Array();
			var string:String = new String();
			for (i = 0; i < numBlocks; i++) {
				cipherBlocks.push(cryptArr.slice(i * 16, (i + 1) * 16));
			}
			for (i = cipherBlocks.length - 1; i >= 0; i--) {
				plainBlocks[i] = decryptBlock(cipherBlocks[i], key);
				plainBlocks[i] = (i === 0) ? xorBlocks(plainBlocks[i], iv) : xorBlocks(plainBlocks[i], cipherBlocks[i - 1]);
			}
			for (i = 0; i < numBlocks - 1; i++) {
				string += block2s(plainBlocks[i], false);
			}
			string += block2s(plainBlocks[i], true);
			return binary ? string : dec_utf8(string);
		}
		
		/**
		 * Encripts block
		 * @param	block block to be encrypted.
		 * @param	words array of round keys.
		 * @return encrypted block.
		 */
		public static function encryptBlock(block:Array, words:Array):Array {
			Decrypt = false;
			var state:Array = addRoundKey(block, words, 0);
			var round:int;
			for (round = 1; round < (Nr + 1); round++) {
				state = subBytes(state);
				state = shiftRows(state);
				if (round < Nr) {
					state = mixColumns(state);
				}
				//last round? don't mixColumns
				state = addRoundKey(state, words, round);
			}
			
			return state;
		}
		
		/**
		 * Decrypts block.
		 * @param	block block to be decrypted.
		 * @param	words array of round keys.
		 * @return decrypted block.
		 */
		public static function decryptBlock(block:Array, words:Array):Array {
			Decrypt = true;
			var state:Array = addRoundKey(block, words, Nr);
			var round:int;
			for (round = Nr - 1; round > -1; round--) {
				state = shiftRows(state);
				state = subBytes(state);
				state = addRoundKey(state, words, round);
				if (round > 0) {
					state = mixColumns(state);
				}
					//last round? don't mixColumns
			}
			
			return state;
		}
		
		private static function subBytes(state:Array):Array {
			var S:Array = Decrypt ? SBoxInv : SBox;
			var temp:Array = new Array();
			var i:int;
			for (i = 0; i < 16; i++) {
				temp[i] = S[state[i]];
			}
			return temp;
		}
		
		private static function shiftRows(state:Array):Array {
			var temp:Array = new Array();
			var shiftBy:Array = Decrypt ? new Array(0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3) : new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);
			var i:int;
			for (i = 0; i < 16; i++) {
				temp[i] = state[shiftBy[i]];
			}
			return temp;
		}
		
		private static function mixColumns(state:Array):Array {
			var t:Array = new Array();
			var c:int;
			if (!Decrypt) {
				for (c = 0; c < 4; c++) {
					t[c * 4] = G2X[state[c * 4]] ^ G3X[state[1 + c * 4]] ^ state[2 + c * 4] ^ state[3 + c * 4];
					t[1 + c * 4] = state[c * 4] ^ G2X[state[1 + c * 4]] ^ G3X[state[2 + c * 4]] ^ state[3 + c * 4];
					t[2 + c * 4] = state[c * 4] ^ state[1 + c * 4] ^ G2X[state[2 + c * 4]] ^ G3X[state[3 + c * 4]];
					t[3 + c * 4] = G3X[state[c * 4]] ^ state[1 + c * 4] ^ state[2 + c * 4] ^ G2X[state[3 + c * 4]];
				}
			} else {
				for (c = 0; c < 4; c++) {
					t[c * 4] = GEX[state[c * 4]] ^ GBX[state[1 + c * 4]] ^ GDX[state[2 + c * 4]] ^ G9X[state[3 + c * 4]];
					t[1 + c * 4] = G9X[state[c * 4]] ^ GEX[state[1 + c * 4]] ^ GBX[state[2 + c * 4]] ^ GDX[state[3 + c * 4]];
					t[2 + c * 4] = GDX[state[c * 4]] ^ G9X[state[1 + c * 4]] ^ GEX[state[2 + c * 4]] ^ GBX[state[3 + c * 4]];
					t[3 + c * 4] = GBX[state[c * 4]] ^ GDX[state[1 + c * 4]] ^ G9X[state[2 + c * 4]] ^ GEX[state[3 + c * 4]];
				}
			}
			
			return t;
		}
		
		private static function addRoundKey(state:Array, words:Array, round:int):Array {
			var temp:Array = new Array();
			var i:int;
			for (i = 0; i < 16; i++) {
				temp[i] = state[i] ^ words[round][i];
			}
			return temp;
		}
		
		private static function xorBlocks(block1:Array, block2:Array):Array {
			var temp:Array = new Array();
			var i:int;
			for (i = 0; i < 16; i++) {
				temp[i] = block1[i] ^ block2[i];
			}
			return temp;
		}
		
		/**
		 * Performs key expansion.
		 * @param	key cypher key.
		 * @return array of round keys.
		 */
		public static function expandKey(key:Array):Array {
			// Expects a 1d number array
			var w:Array = new Array();
			var temp:Array = new Array();
			var i:int;
			var r:Array;
			var t:int;
			var flat:Array = new Array();
			var j:int;
			
			for (i = 0; i < Nk; i++) {
				r = new Array(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
				w[i] = r;
			}
			
			for (i = Nk; i < (4 * (Nr + 1)); i++) {
				w[i] = new Array;
				for (t = 0; t < 4; t++) {
					temp[t] = w[i - 1][t];
				}
				if (i % Nk === 0) {
					temp = subWord(rotWord(temp));
					temp[0] ^= Rcon[i / Nk - 1];
				} else if (Nk > 6 && i % Nk === 4) {
					temp = subWord(temp);
				}
				for (t = 0; t < 4; t++) {
					w[i][t] = w[i - Nk][t] ^ temp[t];
				}
			}
			for (i = 0; i < (Nr + 1); i++) {
				flat[i] = new Array();
				for (j = 0; j < 4; j++) {
					flat[i].push(w[i * 4 + j][0], w[i * 4 + j][1], w[i * 4 + j][2], w[i * 4 + j][3]);
				}
			}
			return flat;
		}
		
		private static function subWord(w:Array):Array { //side effect?
			// apply SBox to 4-byte word w
			var result:Array = new Array();
			var i:int;
			for (i = 0; i < 4; i++) {
				result[i] = SBox[w[i]];
			}
			return result;
		}
		
		private static function rotWord(w:Array):Array { //side effect?
			// rotate 4-byte word w left by one byte
			var tmp:int = w[0];
			var result:Array = new Array();
			var i:int;
			for (i = 0; i < 3; i++) {
				result[i] = w[i + 1];
			}
			result[3] = tmp;
			return result;
		}
		
		// jlcooke: 2012-07-12: added strhex + invertArr to compress G2X/G3X/G9X/GBX/GEX/SBox/SBoxInv/Rcon saving over 7KB, and added encString, decString
		
		private static function invertArr(arr:Array):Array {
			var i:int;
			var ret:Array = new Array();
			for (i = 0; i < arr.length; i++) {
				ret[arr[i]] = i;
			}
			return ret;
		}
		
		private static function Gxx(a:int, b:int):int {
			var i:int;
			var ret:int = 0;
			
			for (i = 0; i < 8; i++) {
				ret = ((b & 1) === 1) ? ret ^ a : ret;
				/* xmult */
				a = (a > 0x7f) ? 0x11b ^ (a << 1) : (a << 1);
				b >>>= 1;
			}
			
			return ret;
		}
		
		private static function Gx(x:int):Array {
			var i:int;
			var r:Array = new Array();
			for (i = 0; i < 256; i++) {
				r[i] = Gxx(x, i);
			}
			return r;
		}
		
		// S-box
		private static var SBox:Array = Util.strhex('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16', 2);
		
		// Precomputed lookup table for the inverse SBox
		private static var SBoxInv:Array = invertArr(SBox);
		
		// Rijndael Rcon
		private static var Rcon:Array = Util.strhex('01020408102040801b366cd8ab4d9a2f5ebc63c697356ad4b37dfaefc591', 2);
		
		private static var G2X:Array = Gx(2);
		
		private static var G3X:Array = Gx(3);
		
		private static var G9X:Array = Gx(9);
		
		private static var GBX:Array = Gx(0xb);
		
		private static var GDX:Array = Gx(0xd);
		
		private static var GEX:Array = Gx(0xe);
		
		/**
		 * Encrypts string as a text.
		 * @param	string
		 * @param	pass
		 * @param	binary
		 * @return encrypted text encoded by Base64
		 */
		public static function enc(string:String, pass:String, binary:Boolean = false):String {
			// string, password in plaintext
			var salt:Array = randArr(8);
			var pbe:Object = openSSLKey(s2a(pass, binary), salt);
			var key:Array = pbe.key;
			var iv:Array = pbe.iv;
			var cipherBlocks:Array;
			var saltBlock:Array = [[83, 97, 108, 116, 101, 100, 95, 95].concat(salt)];
			var _string:Array = s2a(string, binary);
			cipherBlocks = rawEncrypt(_string, key, iv);
			// Spells out 'Salted__'
			cipherBlocks = saltBlock.concat(cipherBlocks);
			return Base64.encode(cipherBlocks);
		}
		
		/**
		 * Decrypts text encrypted by @see gibberish.AESCrypter.enc method.
		 * @param	string
		 * @param	pass
		 * @param	binary
		 * @return derypted text.
		 */
		public static function dec(string:String, pass:String, binary:Boolean = false):String {
			// string, password in plaintext
			var cryptArr:Array = Base64.decode(string);
			var salt:Array = cryptArr.slice(8, 16);
			var pbe:Object = openSSLKey(s2a(pass, binary), salt);
			var key:Array = pbe.key;
			var iv:Array = pbe.iv;
			cryptArr = cryptArr.slice(16, cryptArr.length);
			// Take off the Salted__ffeeddcc
			string = rawDecrypt(cryptArr, key, iv, binary);
			return string;
		}
		
		private static function encString(plaintext:String, key:String, iv:String):String {
			var i:int;
			var _plaintext:Array = s2a(plaintext, false);
			var _key:Array = s2a(key, false);
			var _iv:Array;
			
			for (i = _key.length; i < 32; i++) {
				_key[i] = 0;
			}
			
			if (iv == null) {
				// TODO: This is not defined anywhere... commented out...
				// iv = genIV();
			} else {
				_iv = s2a(iv, false);
				for (i = _iv.length; i < 16; i++) {
					_iv[i] = 0;
				}
			}
			
			var ct:Array = rawEncrypt(_plaintext, _key, _iv);
			var result:Array = _iv;
			for (i = 0; i < ct.length; i++) {
				result[result.length] = ct[i];
			}
			return Base64.encode(result);
		}
		
		private static function decString(ciphertext:String, key:String):String {
			var tmp:Array = Base64.decode(ciphertext);
			var iv:Array = tmp.slice(0, 16);
			var ct:Array = tmp.slice(16, tmp.length);
			var i:int;
			
			var _key:Array = s2a(key, false);
			for (i = _key.length; i < 32; i++) {
				_key[i] = 0;
			}
			
			var pt:String = rawDecrypt(ct, _key, iv, false);
			return pt;
		}
	}
}

