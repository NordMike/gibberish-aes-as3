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
	
	public class Test {
		
		public function Test() {
			throw new Error("Static class.");
		}
		
		/**
		 * Tests library.
		 * @return report on testing.
		 */
		public static function test():String {
			var result:String = new String();
			//FIPS Verification
			
			AESCrypter.size(128);
			var f128block:Array = AESCrypter.h2a("00112233445566778899aabbccddeeff");
			var f128ciph:Array = AESCrypter.h2a("69c4e0d86a7b0430d8cdb78070b4c55a");
			var f128key:Array = AESCrypter.expandKey(AESCrypter.h2a("000102030405060708090a0b0c0d0e0f"));
			if ((AESCrypter.encryptBlock(f128block, f128key).toString() === f128ciph.toString()) && (AESCrypter.decryptBlock(f128ciph, f128key).toString() == f128block.toString())) {
				result += "#f128 Passed!\n";
			} else {
				result += "#f128 Fail!\n";
			}
			
			AESCrypter.size(192);
			var f192block:Array = AESCrypter.h2a("00112233445566778899aabbccddeeff");
			var f192ciph:Array = AESCrypter.h2a("dda97ca4864cdfe06eaf70a0ec0d7191");
			var f192key:Array = AESCrypter.expandKey(AESCrypter.h2a("000102030405060708090a0b0c0d0e0f1011121314151617"));
			if ((AESCrypter.encryptBlock(f192block, f192key).toString() === f192ciph.toString()) && (AESCrypter.decryptBlock(f192ciph, f192key).toString() == f192block.toString())) {
				result += "#f192 Passed!\n";
			} else {
				result += "#f192 Fail!\n";
			}
			
			AESCrypter.size(256);
			var f256block:Array = AESCrypter.h2a("00112233445566778899aabbccddeeff");
			var f256ciph:Array = AESCrypter.h2a("8ea2b7ca516745bfeafc49904b496089");
			var f256key:Array = AESCrypter.expandKey(AESCrypter.h2a("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
			if ((AESCrypter.encryptBlock(f256block, f256key).toString() === f256ciph.toString()) && (AESCrypter.decryptBlock(f256ciph, f256key).toString() == f256block.toString())) {
				result += "#f256 Passed!\n";
			} else {
				result += "#f256 Fail!\n";
			}
			
			// OpenSSL Compat
			
			// Encryption
			
			// echo -n "secretsecretsecret" | openssl enc -e -a -aes-128-cbc -K 5e884898da28047151d0e56f8dc62927 -iv 6bbda7892ad344e06c31e64564a69a9a
			// 4j+jnKTSsTBVUJ9MuV8hFEHuxdyT065rYbUqo0gJo1I= Hex: e23fa39ca4d2b13055509f4cb95f211441eec5dc93d3ae6b61b52aa34809a352
			AESCrypter.size(128);
			var key:Array = AESCrypter.h2a("5e884898da28047151d0e56f8dc62927"); //sha256 of "password"
			var iv:Array = AESCrypter.h2a("6bbda7892ad344e06c31e64564a69a9a");
			var plaintext:Array = AESCrypter.s2a("secretsecretsecret");
			var openssl:String = "4j+jnKTSsTBVUJ9MuV8hFEHuxdyT065rYbUqo0gJo1I=\n";
			var enc:Array = AESCrypter.rawEncrypt(plaintext, key, iv);
			if (Base64.encode(enc) == openssl) {
				result += "#oe128 Passed!\n";
			} else {
				result += "#oe128 Fail!\n";
			}
			
			// echo -n "secretsecretsecret" | openssl enc -e -a -aes-192-cbc -K 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd6 -iv 6bbda7892ad344e06c31e64564a69a9a
			// g1D8nfnp31TH8jaV3304KP23i6aQhSaU3gubyGtV6WE= Hex: 8350fc9df9e9df54c7f23695df7d3828fdb78ba690852694de0b9bc86b55e961
			AESCrypter.size(192);
			var password:Array = AESCrypter.h2a("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd6"); //sha256 of "password"
			iv = AESCrypter.h2a("6bbda7892ad344e06c31e64564a69a9a");
			plaintext = AESCrypter.s2a("secretsecretsecret");
			openssl = "g1D8nfnp31TH8jaV3304KP23i6aQhSaU3gubyGtV6WE=\n";
			enc = AESCrypter.rawEncrypt(plaintext, password, iv);
			if (Base64.encode(enc) == openssl) {
				result += "#oe192 Passed!\n";
			} else {
				result += "#oe192 Fail!\n";
			}
			
			// echo -n "secretsecretsecret" | openssl enc -e -a -aes-256-cbc -K 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -iv 6bbda7892ad344e06c31e64564a69a9a
			// XUfDIa3urWyzHC1bmfmSQJjaTEXPmKkQYvbCnYd6gFY= Hex: 5d47c321adeead6cb31c2d5b99f9924098da4c45cf98a91062f6c29d877a8056
			AESCrypter.size(256);
			password = AESCrypter.h2a("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"); //sha256 of "password"
			iv = AESCrypter.h2a("6bbda7892ad344e06c31e64564a69a9a");
			plaintext = AESCrypter.s2a("secretsecretsecret");
			openssl = "XUfDIa3urWyzHC1bmfmSQJjaTEXPmKkQYvbCnYd6gFY=\n";
			enc = AESCrypter.rawEncrypt(plaintext, password, iv);
			if (Base64.encode(enc) == openssl) {
				result += "#oe256 Passed!\n";
			} else {
				result += "#oe256 Fail!\n";
			}
			
			// Decryption
			
			AESCrypter.size(128);
			result += "#od128 " + AESCrypter.dec("U2FsdGVkX19SF/vHKUf1zS4SMlbROLLCRiyprMJuQ+1nzQJyatGmJhC9xJ6Od+vcZtgZyurEqeEkna1Kj4gqdw==", "pass") + "\n";
			AESCrypter.size(192);
			result += "#od192" + AESCrypter.dec("U2FsdGVkX18EDbSr5+mGnFZRUwSTISFzadp7wsC/kTgtco+fQ4hMMrJ1zpePN6sicBnAOaC+p/vCmgb3zBc7Ag==", "pass") + "\n";
			AESCrypter.size(256);
			result += "#od256" + AESCrypter.dec("U2FsdGVkX1+f4uMd56OoVkwmaLStldQEHRNSGa1gRVF0XUvNNIr4Vg1PWa+0HHpiTRmvKXFSY90SrJea4Cb+zA==", "pass") + "\n";
			
			// PBE Testing
			
			AESCrypter.size(128);
			password = AESCrypter.s2a("mumstheword")
			var salt:Array = AESCrypter.h2a("C3CA5EE98B8F1FC5")
			key = AESCrypter.h2a("1D189274EB848A8CD1F3D029030E0E5A")
			iv = AESCrypter.h2a("ED562A01653B3973C4507CF2B97F3641")
			var pbe:Object = AESCrypter.openSSLKey(password, salt);
			if ((AESCrypter.a2h(pbe.key) == AESCrypter.a2h(key)) && (AESCrypter.a2h(pbe.iv) == AESCrypter.a2h(iv))) {
				result += "#pbe128 Passed!\n";
			} else {
				result += "#pbe128 Fail!\n";
			}
			
			AESCrypter.size(192);
			password = AESCrypter.s2a("mumstheword");
			salt = AESCrypter.h2a("6C96EB8089668585");
			key = AESCrypter.h2a("1A5EC3EB94BF5A675B2CE79E30D84EA8E68936A7E17FFCC7");
			iv = AESCrypter.h2a("6E82636638721A2C7B92FB6EE007C3BC");
			pbe = AESCrypter.openSSLKey(password, salt);
			if ((AESCrypter.a2h(pbe.key) == AESCrypter.a2h(key)) && (AESCrypter.a2h(pbe.iv) == AESCrypter.a2h(iv))) {
				result += "#pbe192 Passed!\n";
			} else {
				result += "#pbe192 Fail!\n";
			}
			
			AESCrypter.size(256);
			password = AESCrypter.s2a("mumstheword");
			salt = AESCrypter.h2a("5F934E4432AEB8B3");
			key = AESCrypter.h2a("3d6b59e8c5623ce4ff7c165995b209e7f03461ec057ca33a5cd1559d01e5682b");
			iv = AESCrypter.h2a("5be59eadbed053db61bd9e413fb8b7d5");
			pbe = AESCrypter.openSSLKey(password, salt);
			if ((AESCrypter.a2h(pbe.key) == AESCrypter.a2h(key)) && (AESCrypter.a2h(pbe.iv) == AESCrypter.a2h(iv))) {
				result += "#pbe256 Passed!\n";
			} else {
				result += "#pbe256 Fail!\n";
			}
			
			//AESCrypter.rawDecrypt("dd52055f3e2348a864115fd06979e6c8", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "6bbda7892ad344e06c31e64564a69a9a")
			// "f4XTQBzF6h+B0T+P9bfqUKHO1nhsZAmYbmP55VHMmxZqTsx9Nhi0SZVck+0onxmsgAXxaEqyUmztv3726w0Kb03LpfOGszmQOQvwwmkV5goeB1oTKWThz+cIGh4qZcdnc/+Cq0sQ7QFBpkwhaFyFf2z2zDos+2hGr2qs04Jlj8Wx5fQTPWwFnsxKV4+rmqswnWwY6dNjxFi5LQ+aecPw0eDFQzZZuOgsFbreXMYzMWFzyH07khQfA5V45FhgOyq7ulmikUnahjupzlpL4lTaHMx6CU3gZo6E6+Ip5CANFwC0qhPP0Ekhdni5VjYz0Qw7"
			// "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			
			//UTF-8 Verify
			AESCrypter.size(128);
			var chinese:String = " 版面变化复";
			var encS:String = AESCrypter.enc(chinese, "secret");
			var decS:String = AESCrypter.dec(encS, "secret");
			result += "#u128 Before: " + chinese + "\n";
			result += "#u128 After: " + decS + "\n";
			
			AESCrypter.size(192);
			chinese = " 版面变化复";
			encS = AESCrypter.enc(chinese, "secret");
			decS = AESCrypter.dec(encS, "secret");
			result += "#u192 Before: " + chinese + "\n";
			result += "#u192 After: " + decS + "\n";
			
			AESCrypter.size(256);
			chinese = " 版面变化复";
			encS = AESCrypter.enc(chinese, "secret");
			decS = AESCrypter.dec(encS, "secret");
			result += "#u256 Before: " + chinese + "\n";
			result += "#u256 After: " + decS + "\n";
			
			return result;
		}
		
		/**
		 * Performs benchmark of library.
		 * @return report on benchmarking.
		 */
		public static function benchmark():String {
			var result:String = new String();
			//Benchmarks
			
			AESCrypter.size(256);
			var text:String = "Something small to encode, lets hope it's quite quick";
			var start:Date = new Date();
			for (var i:int = 0; i < 100; i++) {
				AESCrypter.enc(text, "secret");
			}
			var end:Date = new Date();
			result += "#enc " + ((end.time - start.time) / 1000) + " seconds\n";
			
			var crypt:String = "U2FsdGVkX1+qbsRBKWqv3Hs8F187/SvIivffz/8tosmb4JocDocxBSTxAIWn1KkzlBRcIdYnlOKhgyJboCHn5SvQw+CDc/RLy2UIKGV2LpI=";
			start = new Date();
			for (i = 0; i < 100; i++) {
				AESCrypter.dec(crypt, "secret");
			}
			end = new Date();
			result += "#dec " + ((end.time - start.time) / 1000) + " seconds\n";
			
			var bigtext:String = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Etiam volutpat. Sed rhoncus mauris. Proin pellentesque felis in est. Vestibulum bibendum. Etiam nec augue id justo congue interdum. Sed magna. Praesent ac enim. Fusce tempor nibh a elit. Maecenas eget sem nec pede posuere aliquet. Duis ut dolor at purus eleifend sodales. Nulla bibendum volutpat lectus. Suspendisse potenti. Morbi tortor risus, semper a, faucibus nec, lacinia eu, lacus. Integer eros orci, semper quis, congue vitae, lobortis sed, nisl. Nulla sagittis lorem eget velit. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Sed facilisis ante nec lacus. Maecenas et tortor. Sed eleifend orci vel elit. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Sed dolor magna, dapibus id, malesuada vel, luctus non, enim. Etiam pretium nibh quis nunc. Proin egestas nibh nec diam. Proin tellus nisi, tincidunt ac, eleifend ac, aliquet id, tortor. Integer luctus pharetra massa. Nulla facilisi. Sed ante odio, euismod eu, adipiscing id, luctus sit amet, nunc. Vivamus odio. Donec congue orci a felis. Duis lacinia, odio sed tincidunt rhoncus, augue magna tempus magna, ut feugiat felis dui ut odio. Phasellus cursus sapien vitae nulla. Nunc urna. Aliquam dapibus enim sed neque. In ornare luctus nunc. Sed augue neque, luctus sit amet, feugiat vitae, varius at, metus. Donec tellus est, pulvinar ut, faucibus eu, imperdiet vitae, nibh. Donec quis sem id sem sodales interdum. Vivamus eget velit. Fusce convallis mi ac est. Suspendisse justo. Morbi eu neque. Nullam non lacus. Fusce lobortis. Aenean dignissim ligula quis erat lacinia ornare. Nunc accumsan, velit at ultrices tincidunt, enim libero adipiscing sem, eu tempor mauris erat tempor massa. Duis nibh est, tempus a, pretium at, tempor at, dui. Pellentesque erat purus, viverra a, porttitor at, vulputate ut, enim. Aliquam et nisi. Nam ultrices. Donec ut lorem. Nam accumsan magna vitae risus eleifend lobortis. Fusce metus velit, luctus vel, dictum quis, fringilla id, nisi. Aenean et lectus a eros viverra vehicula. Nulla imperdiet laoreet velit. Quisque et est vitae felis commodo lacinia. Etiam bibendum risus. Maecenas lorem risus, porta ac, viverra rutrum, ultrices nec, purus. Phasellus sagittis accumsan elit. Nam venenatis, magna non pretium eleifend, massa eros hendrerit libero, at ultricies dui quam venenatis ante. Ut ultricies tristique dui. Donec volutpat dignissim diam. Maecenas vel massa eget nibh malesuada fermentum. Pellentesque lacinia. In eget est. Vestibulum vel nibh. Sed scelerisque risus et tortor. Phasellus hendrerit. Duis nec erat sed justo vestibulum pretium. Cras rhoncus mollis nisi. Proin rutrum. Morbi lorem. Proin ut felis faucibus pede cursus elementum. Donec dui. Nam nec nisl. Praesent tincidunt massa. Morbi dapibus interdum urna. Duis consectetuer. Fusce quam tortor, consectetuer at, ultricies sed, lacinia quis, diam. Maecenas nisl. Vestibulum auctor fringilla diam. Vestibulum tortor augue, lacinia sed, viverra nec, porta vitae, quam. Nunc sagittis porttitor risus. Integer justo. Integer sagittis, quam eget fermentum vulputate, ante felis lacinia turpis, vitae scelerisque magna erat eget enim. Nunc rhoncus libero vitae erat. Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aliquam id arcu in metus tincidunt accumsan. In hac habitasse platea dictumst. Proin mauris. Cras mollis urna at ante. Nullam non dolor. Nulla blandit. Vivamus vel urna ac erat pulvinar volutpat. Nullam porttitor. Nunc vel mauris. Aliquam velit. In tempor, ipsum vestibulum aliquet viverra, felis odio lobortis sapien, at dapibus est libero venenatis felis. Nulla bibendum sodales leo. In in nisl. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Pellentesque bibendum, sapien vitae posuere pulvinar, nisl lorem cursus orci, id porta leo arcu ut nisl. Cras nisi nisi, posuere elementum, porttitor ac, porttitor a, dolor. Integer nullam. Nullam porttitor. Nunc vel mauris. Aliquam velit.Nullam porttitor. Nunc vel mauris. Nunc";
			start = new Date();
			var big_crypt:String = '';
			for (i = 0; i < 5; i++) {
				big_crypt = AESCrypter.enc(bigtext, "secret");
			}
			end = new Date();
			result += "#bigenc " + ((end.time - start.time) / 1000) + " seconds\n";
			
			start = new Date();
			for (i = 0; i < 5; i++) {
				AESCrypter.dec(big_crypt, "secret");
			}
			end = new Date();
			result += "#bigdec " + ((end.time - start.time) / 1000) + " seconds\n";
			
			return result;
		}
	}

}

