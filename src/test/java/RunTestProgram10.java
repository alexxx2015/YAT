import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.LinkedList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import edu.tum.uc.transformer.MainTransformer;

public class RunTestProgram10 extends BasicTest {

	@Before
	public void init() {
		this.mclWhiteList = "test";
		super.init();
	}

	@Test
	public void runjzip() throws IOException, IllegalClassFormatException {
		List<String> clazzes = new LinkedList<String>();
		clazzes.add("test.IDataMover");
		clazzes.add("test.TestIntf");
		clazzes.add("test.TestProgram10");
		clazzes.add("test.DataMover");
		
		Object runTest = null;
		for (String clazz : clazzes) {
			String className = clazz.replace(".", System.getProperty("file.separator"));
//			InputStream is = this.mcl.getResourceAsStream(className);
			byte[] rawClass = this.mcl.getResourceAsByte(className);//IOUtils.toByteArray(is);

			MainTransformer t = new MainTransformer("tracker.properties");
			byte[] instrumentedClass = t.transform(this.mcl, clazz, null, null, rawClass);
			File f = new File(this.INSTRUMENTDIR + clazz.replace(".", "/") + ".class");
			f.getParentFile().mkdirs();
			FileOutputStream fos = new FileOutputStream(f);
			fos.write(instrumentedClass);
			fos.close();

			// Reload instrumented JZip class and execute test run: zip a
			// bunch of file in the resource folder 'toBeZippedFiles'
			try {
				Class<?> reloadClass = this.mcl.redefine(clazz.replace("/", "."), instrumentedClass);
				if (clazz.equals("test.TestProgram10")) {
					runTest = reloadClass.newInstance();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		if (runTest != null){
			try {
				Method m = runTest.getClass().getDeclaredMethod("runtest", null);
				m.invoke(runTest, null);
			} catch (NoSuchMethodException | SecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
