package soot.jimple.infoflow.test;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class MyTestCode {
	
	public void implicitFlow() throws IOException {
		int output = 0;
		String secret = "", secret2 = "";

		BufferedReader fr = new BufferedReader(new FileReader("secret.txt"));
		secret = fr.readLine();
		fr.close();
		
		BufferedReader fr2 = new BufferedReader(new FileReader("secret2.txt"));
		secret2 = fr2.readLine();
		fr2.close();

		output = checkSecret(secret);

		System.out.println(output);
		printstring(secret2);
	}
	private int checkSecret(String p_secret) {
		if ("mysecret".equals(p_secret))
			return 1;
		return 0;
	}
	private void printstring(String s) {
		System.out.println(s);
	}
	
	public void writer() throws IOException {
		String secret = "";
		BufferedReader fr = new BufferedReader(new FileReader("secret.txt"));
		secret = fr.readLine();
		fr.close();		
		
		System.out.write(secret.getBytes());
	}
	
	public class myclass{
		public void m(String param){
			System.out.print(param);
		}
	}
	public class myclass2{
		public void m2(String param){
			myclass _myclass = new myclass();
			_myclass.m(param);
		}
	}

	public void interfaceTestCode() throws IOException{
		SourceIntf source = new SourceImpl("mysecret");
		SinkIntf sink = new SinkImpl();
		moveData(source,sink);


//		String secret = "";
//		BufferedReader fr = new BufferedReader(new FileReader("secret.txt"));
//		secret = fr.readLine();
//		fr.close();		
//		System.out.println(secret);
	}
	
	private void moveData(SourceIntf source, SinkIntf sink){
		sink.setData(source.getData());
	}
}
