import edu.tum.uc.transformer.ReflectionHandler;
import edu.tum.uc.transformer.RuntimeTracker;

public class Test {

	private int myvar = 188;

	public static void main(String[] args) {
		Integer i = new Integer(33), j = new Integer(3223) ;
		RuntimeTracker.addTaint(i, 4711);
		RuntimeTracker.addTaint(j, 4712);
		System.out.println(RuntimeTracker.getTaint(i));
		System.out.println(RuntimeTracker.getTaint(j));
	}
}
