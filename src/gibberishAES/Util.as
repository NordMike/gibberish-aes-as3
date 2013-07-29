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
	
	public class Util {
		
		public function Util() {
			throw new Error("Static class");
		}
		
		public static function strhex(str:String, size:int):Array {
			var i:int;
			var result:Array = new Array();
			for (i = 0; i < str.length; i += size) {
				result[i / size] = parseInt(str.substr(i, size), 16);
			}
			return result;
		}
		
		public static function hexstr(hex:Array, size:int):String {
			var i:int;
			var j:int;
			var result:String = new String();
			var tmp:String;
			for (i = 0; i < hex.length; i++) {
				tmp = hex[i].toString(16);
				if (tmp.length > size)
					tmp = tmp.substr(tmp.length - size, size);
				else if (tmp.length < size) {
					for (j = 0; j < size - tmp.length; j++)
						tmp = '0' + tmp;
				}
				result += tmp;
			}
			return result;
		}
	
	}

}