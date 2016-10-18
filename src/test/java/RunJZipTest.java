import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.IllegalClassFormatException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import edu.tum.uc.transformer.MainTransformer;


public class RunJZipTest extends BasicTest {
	
	@Test
	public void runtest() throws IOException, IllegalClassFormatException{
		Class<?> clazz = jzip.JZip.class;
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
		fos.close();
	}

}
