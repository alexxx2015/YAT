import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class MyClassLoader extends ClassLoader {
	private String whiteList;
	private String rootDir;

	public MyClassLoader(ClassLoader parent, String whiteList, String rootDir) {
		super(parent);
		this.whiteList = whiteList;
		this.rootDir = rootDir;
	}

	public Class<?> redefine(String className, byte[] bytecode) {
		return super.defineClass(className, bytecode, 0, bytecode.length);
	}

	public Class<?> loadClass(String name) throws ClassNotFoundException {
		if (!name.startsWith(this.whiteList))
			return super.loadClass(name);

		try {
			String url = "file:C:/data/projects/tutorials/web/WEB-INF/" + "classes/reflection/MyObject.class";
			url = "file:" + this.rootDir + name.replace(".", "/") + ".class";
			URL myUrl = new URL(url);
			URLConnection connection = myUrl.openConnection();
			InputStream input = connection.getInputStream();
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			int data = input.read();

			while (data != -1) {
				buffer.write(data);
				data = input.read();
			}

			input.close();

			byte[] classData = buffer.toByteArray();

			return defineClass(name, classData, 0, classData.length);

		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	public byte[] getResourceAsByte(String name) {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try {
			String url = "file:C:/data/projects/tutorials/web/WEB-INF/" + "classes/reflection/MyObject.class";
			url = "file:" + this.rootDir + name.replace(".", "/") + ".class";
			URL myUrl = new URL(url);
			URLConnection connection = myUrl.openConnection();
			InputStream input = connection.getInputStream();
			int data = input.read();

			while (data != -1) {
				buffer.write(data);
				data = input.read();
			}

			input.close();

		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		byte[] classData = buffer.toByteArray();
		return classData;
	}
}
