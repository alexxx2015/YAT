import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import reflection.SinkRef;

//sun.reflect.NativeMethodAccessorImpl
public class RunTestRef {
	
	public static void main(String[] args){
		String s = "Hello World";
		SinkRef sink = new SinkRef();
		try {
			Method m = sink.getClass().getMethod("output", String.class);
			m.invoke(sink, s);
		} catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
