/**
 * @license Test viewing class
 * License: MIT
 */

package {
	import flash.display.MovieClip;
	import flash.text.TextField;
	import gibberishAES.Test;
	
	public class TestViewer extends MovieClip {
		
		private var txt:TextField = new TextField();
		public function TestViewer() {
			txt.width = stage.stageWidth;
			txt.height = stage.stageHeight;
			addChild(txt);
			txt.appendText("Testing:\n\n");
			txt.appendText(Test.test());
			txt.appendText("\n\nBenchmarking:\n\n");
			txt.appendText(Test.benchmark());
		}
	
	}

}