
public class LambdaTest {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Runnable r2 = () -> System.out.println("Hello World ");
		r2.run();
		
		LambdaTestIntf intf = (String s) -> {System.out.println(s); System.out.println("SS: "+s);};
		intf.doSth("Test");
	}
	
	public interface LambdaTestIntf{
		public void doSth(String s);
	}
}
