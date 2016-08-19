package edu.tum.uc.tomcat;
import org.apache.tomcat.util.descriptor.web.FragmentJarScannerCallback;
import org.apache.tomcat.util.descriptor.web.WebXmlParser;
public class TomcatJarScannerCallback extends FragmentJarScannerCallback{

	public TomcatJarScannerCallback(WebXmlParser webXmlParser, boolean delegate, boolean parseRequired) {
		super(webXmlParser, delegate, parseRequired);
		// TODO Auto-generated constructor stub
	}
	
	public void scanWebInfClasses(){
	}

}
