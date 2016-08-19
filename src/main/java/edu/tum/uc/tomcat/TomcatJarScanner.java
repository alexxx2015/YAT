package edu.tum.uc.tomcat;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;

import javax.servlet.ServletContext;

import org.apache.tomcat.util.scan.Constants;
import org.apache.tomcat.util.scan.StandardJarScanner;

import org.apache.tomcat.JarScanFilter;
import org.apache.tomcat.JarScanType;
import org.apache.tomcat.JarScannerCallback;

public class TomcatJarScanner extends StandardJarScanner {
	private TomcatJarScannerCallback myCallback;

	private ArrayList<String> classpath;

	@Override
	public JarScanFilter getJarScanFilter() {
		// TODO Auto-generated method stub
		return super.getJarScanFilter();
	}

	@Override
	public void scan(JarScanType arg0, ServletContext context,
			JarScannerCallback arg2) {
		// TODO Auto-generated method stub
		super.scan(arg0, context, arg2);

		// Scan WEB-INF/classes
		try {

			this.classpath = new ArrayList<String>();
			// Scan WEB-INF/lib
			Set<String> dirList = context
					.getResourcePaths(Constants.WEB_INF_LIB);
			if (dirList != null) {
				Iterator<String> it = dirList.iterator();
				while (it.hasNext()) {
					String path = it.next();
					if (path.endsWith(Constants.JAR_EXT)) {
						classpath.add(path);
						System.out.println("TOMCATJARSCANNER: "
								+ context.getResource(Constants.WEB_INF_LIB)
										.getPath() + path.substring(1, path.length()));
					}
				}
			}
			URL url = context.getResource("/WEB-INF/classes");
			System.out.println("TOMCATJARSCANNER 2: " + url.getPath());
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void setJarScanFilter(JarScanFilter arg0) {
		// TODO Auto-generated method stub
		super.setJarScanFilter(arg0);
	}

}
