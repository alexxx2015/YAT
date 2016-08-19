import java.lang.reflect.Field;

import edu.tum.uc.transformer.taint.TaintWrapper;

public class TestClient extends Test {
	
	private String mystring;
	public static void main(String[] args){
		TestClient tc = new TestClient();
		Field[] fields = TestClient.class.getSuperclass().getDeclaredFields();
		for(Field f : fields){
			System.out.println(f.getName());
			f.setAccessible(true);
			try {
				System.out.println(f.getInt(tc));
				f.setInt(tc, 78);
				System.out.println(f.getInt(tc));
			} catch (IllegalArgumentException | IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public void test(){
		Object[] o = new Object[11];
		String[] s = (String[])o;
		
		Object o2 = new Object();
		String sn = (String)o2;
		
		int[] i = new int[44];
		System.out.println(i.length);
		p("Test");
	}
	
	public static void p(Object o){
		TaintWrapper<String[],Integer[]> t = TaintWrapper.getWrapper(new String[]{"Hello","world"}, new int[2]);
		t.value = new String[]{"hh","kk"};
		System.out.println(4);
	}
}
