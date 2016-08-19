package soot.jimple.infoflow.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class DataContainerMain {	

	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		FileInputStream fis1 = new FileInputStream(new File("D1.txt"));
//		FileInputStream fis2 = new FileInputStream(new File("D2.txt"));
		byte[] b1 = read(new byte[100],fis1);
//		byte[] b2 = read(new byte[100], fis2);
		//fis1.read(b1);
		//fis2.read(b2);
		
		String s1 = new String(b1, StandardCharsets.UTF_8);
//		s1 = new String("test");
//		String s2 = new String(b2, StandardCharsets.UTF_8);
		
//		DataContainer d1 = new DataContainerImpl();
//		d1.setData(s1);
		
//		DataContainer d2 = new DataContainerImpl();
//		d2.setData(s2);
		
//		moveData(d1, d2);

		FileOutputStream fos = new FileOutputStream(new File("D3.txt"));
//		fos.write(d2.getData().getBytes());
		fos.write(s1.getBytes());
		fos.close();
//		fos.write(b1);
	}
	
	private static void moveData(DataContainer d1, DataContainer d2){
		String dataD1 = d1.getData();
		d1.setData(d2.getData());
		d2.setData(dataD1);
	}
	public static byte[] read(byte[] b, FileInputStream reader) throws IOException{
		reader.read(b);
		return b;
	}

}
