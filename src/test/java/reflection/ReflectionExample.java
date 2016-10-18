package reflection;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

//sun.reflect.NativeMethodAccessorImpl
public class ReflectionExample {
	
	public static void main(String[] args){
		SourceReflection source = new SourceReflection();
		SinkReflection sink = new SinkReflection();
		try {
			Method mGetVal = source.getClass().getMethod("getIntValue", null);
			int s = (int) mGetVal.invoke(source, null);
			Method mOutput = sink.getClass().getMethod("output", int.class);
			mOutput.invoke(sink,s);
		} catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
