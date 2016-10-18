import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.IllegalClassFormatException;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import edu.tum.uc.transformer.MainTransformer;

public class RunReflectionExample extends BasicTest {

	@Test
	public void runtest() throws IOException, IllegalClassFormatException {
		List<Class<?>> classes = new LinkedList<Class<?>>();
		classes.add(reflection.ReflectionExample.class);
		classes.add(reflection.SinkReflection.class);
		classes.add(reflection.SourceReflection.class);

		for (Class clazz : classes) {
			String className = clazz.getName().replace(".", System.getProperty("file.separator")) + ".class";
			InputStream is = clazz.getClassLoader().getResourceAsStream(className);
			byte[] rawClass = IOUtils.toByteArray(is);

			MainTransformer t = new MainTransformer("tracker.properties");
			byte[] instrumentedClass = t.transform(this.getClass().getClassLoader(), clazz.getCanonicalName(), null,
					null, rawClass);

			File f = new File("/home/alex/instrumented/" + clazz.getName().replace(".", "/") + ".class");
			f.getParentFile().mkdirs();
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(instrumentedClass);
			fos.close();
			System.out.println("DUMPED " + clazz.getName() + " to " + f.getAbsolutePath());
		}
	}

}
