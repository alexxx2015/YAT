import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.IllegalClassFormatException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import edu.tum.uc.transformer.MainTransformer;


public class RunTestProgram10 extends BasicTest{
	
	@Test
	public void runjzip() throws IOException, IllegalClassFormatException{
//		this.instrumentor.instrument("jzip.JZip");
		Class<?> clazz = test.TestProgram10.class;
		String className = clazz.getName().replace(".",
				System.getProperty("file.separator"))
				+ ".class";			
		InputStream is = clazz.getClassLoader().getResourceAsStream(
				className);
		byte[] rawClass = IOUtils.toByteArray(is);
		
		MainTransformer t = new MainTransformer("tracker.properties");
		byte[] instrumentedClass = t.transform(this.getClass().getClassLoader(), clazz.getCanonicalName(), null, null, rawClass);
		File f = new File("/home/alex/instrumented/"+clazz.getName().replace(".", "/")+".class");
		f.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(instrumentedClass);
	}
}
