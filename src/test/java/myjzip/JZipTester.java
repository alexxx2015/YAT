package myjzip;
//package jzip;
//
//import java.io.BufferedInputStream;
//import java.io.BufferedOutputStream;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.FilterOutputStream;
//import java.io.IOException;
//import java.io.OutputStream;
//import java.lang.reflect.Field;
//import java.util.zip.ZipEntry;
//import java.util.zip.ZipOutputStream;
//
//import edu.tum.uc.jvm.utility.UnsafeUtil;
//
//public class JZipTester {
//
//	public static void main(String[] args) throws Exception{
//		// TODO Auto-generated method stub
//		
//
//		long address = 4723499;
//		StringBuilder s = new StringBuilder("22");
//		address = UnsafeUtil.getObjectAddress(s);
//		s = null;
//		System.gc();
//		Thread.sleep(1000);
//		StringBuilder olds = (StringBuilder) UnsafeUtil.objectFromAddress(address);
//		olds.append("teest");
//		
//		
//		try {
//			byte[] buffer = new byte[32768];
//			String zipFile = "/home/alex/test.zip";
//			String[] fileList = new String[] { "/home/alex/tmp/Demirbas.jar", "/home/alex/tmp/report.xml",
//					"/home/alex/tmp/test.xml" };
//			FileOutputStream fos = new FileOutputStream(zipFile);
//			BufferedOutputStream bos = new BufferedOutputStream(fos, 16384);
//			ZipOutputStream zos = new ZipOutputStream(bos);
//
//			System.out.println("Output to Zip : " + zipFile);
//			for (String file : fileList) {
//				int i = 0;
//
//				System.out.println("File Added : " + file);
//				ZipEntry ze = new ZipEntry(file);
//				zos.putNextEntry(ze);
//
//				FileInputStream in = new FileInputStream(file);
//				BufferedInputStream bin = new BufferedInputStream(in, 32768);
//
//				int len;
//				while ((len = bin.read(buffer)) > 0) {
//					if(i == 1){						
//						Field out = FilterOutputStream.class.getDeclaredField("out");
//						out.setAccessible(true);
//						OutputStream oldOs = (OutputStream) out.get(zos);
//						address = UnsafeUtil.getObjectAddress(oldOs);
//						
//						out.set(zos, new OutputStream() { 
//							public void write(int b) throws IOException{
//								System.out.println("DummyOS");
//							}
//						});
//						oldOs.close();
//						bos = null;
//						
//					}else if (i == 2){
//						OutputStream oldOs = (OutputStream) UnsafeUtil.objectFromAddress(address);
//						if(oldOs != null && oldOs.getClass().getName().equals(BufferedOutputStream.class.getName())){
//							System.out.println("Ok");
//						}
//					}
//					i++;
//					zos.write(buffer, 0, len);
//				}
//
//				in.close();
//			}
//
//			zos.closeEntry();
//			// remember close it
//			zos.close();
//		} catch (Exception e) {
//		}
//	}
//	
//	
//
//}
