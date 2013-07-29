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
	
	public class Base64 {
		
		// Takes a Nx16x1 byte array and converts it to Base64
		public function Base64() {
			throw new Error("Static class.");
		}
		private static const _chars:String = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
		private static var chars:Array = _chars.split('');
		
		public static function encode(b:Array, withBreaks:Boolean = false):String {
			var flatArr:Array = new Array();
			var b64:String = new String();
			var i:int;
			var broken_b64:String;
			var totalChunks:int = Math.floor(b.length * 16 / 3);
			for (i = 0; i < b.length * 16; i++) {
				flatArr.push(b[Math.floor(i / 16)][i % 16]);
			}
			for (i = 0; i < flatArr.length; i = i + 3) {
				b64 += chars[flatArr[i] >> 2];
				b64 += chars[((flatArr[i] & 3) << 4) | (flatArr[i + 1] >> 4)];
				if (flatArr[i + 1] !== undefined) {
					b64 += chars[((flatArr[i + 1] & 15) << 2) | (flatArr[i + 2] >> 6)];
				} else {
					b64 += '=';
				}
				if (flatArr[i + 2] !== undefined) {
					b64 += chars[flatArr[i + 2] & 63];
				} else {
					b64 += '=';
				}
			}
			// OpenSSL is super particular about line breaks
			broken_b64 = b64.slice(0, 64) + '\n';
			for (i = 1; i < (Math.ceil(b64.length / 64)); i++) {
				broken_b64 += b64.slice(i * 64, i * 64 + 64) + (Math.ceil(b64.length / 64) === i + 1 ? '' : '\n');
			}
			return broken_b64;
		}
		
		public static function decode(string:String):Array {
			string = string.replace(/\n/g, '');
			var flatArr:Array = new Array();
			var c:Array = new Array();
			var b:Array = new Array();
			var i:int;
			for (i = 0; i < string.length; i = i + 4) {
				c[0] = _chars.indexOf(string.charAt(i));
				c[1] = _chars.indexOf(string.charAt(i + 1));
				c[2] = _chars.indexOf(string.charAt(i + 2));
				c[3] = _chars.indexOf(string.charAt(i + 3));
				
				b[0] = (c[0] << 2) | (c[1] >> 4);
				b[1] = ((c[1] & 15) << 4) | (c[2] >> 2);
				b[2] = ((c[2] & 3) << 6) | c[3];
				flatArr.push(b[0], b[1], b[2]);
			}
			flatArr = flatArr.slice(0, flatArr.length - (flatArr.length % 16));
			return flatArr;
		}
	}

}