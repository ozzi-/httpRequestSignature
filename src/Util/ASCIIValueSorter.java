package Util;
import java.util.Comparator;

/**
 * Sorts strings based on the single character's ASCII value.
 * 
 * 
 * Example Input:
 * [ test3, test, tESt, TesT, test12, test2, test1, aest, }est, _est]
 * Example Output:
 * [_est, aest, test, tESt, TesT, test12, test1, test2, test3, }est]
 *
 * Note: All strings will be treated as lower case.
 */
public class ASCIIValueSorter implements Comparator<String> {
	@Override
	public int compare(String o1, String o2) {
		o1=o1.toLowerCase();
		o2=o2.toLowerCase();
		int o1L = o1.length();
		int o2L = o2.length();
		int shorterL = (o1L <= o2L?o1L:o2L);
	
		for (int i = 0; i < shorterL; i++) {
			int o1CAscii = o1.charAt(i);
			int o2CAscii = o2.charAt(i);
			if(o1CAscii==o2CAscii) {
				// if we are at the end of the shorter string 
				// and they are equal up till now, 
				// the shorter string comes first in the ordering
				if(i <= shorterL) { 
					return o1L > o2L ? 1 : -1;
				}
				continue;
			}
	        return o1CAscii > o2CAscii ? 1 : -1;
		}
		return 0; // this is the case when we have two empty strings
	}
}