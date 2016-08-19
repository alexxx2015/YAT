import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

public class Misc {

	public static void main(String[] args){
		System.out.println("BYTE: "+Byte.MIN_VALUE+" , "+Byte.MAX_VALUE);
		System.out.println("SHORT: "+Short.MIN_VALUE+" , "+Short.MAX_VALUE);
	}
	public static void m() throws IOException {
		// TODO Auto-generated method stub
		Properties p = new Properties();
		p.put("key1", "value1");
		p.put("key2", "value2");
		FileOutputStream fos = new FileOutputStream("tracker.properties");
		p.storeToXML(fos, "Tracker configuration file");
	}

}
