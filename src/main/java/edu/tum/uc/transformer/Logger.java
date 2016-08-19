package edu.tum.uc.transformer;

public class Logger {
	
	public static void log(int i, String text){
		System.out.println(text+"; TAINT: "+i);
	}

}
