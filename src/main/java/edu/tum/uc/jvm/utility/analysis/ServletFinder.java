package edu.tum.uc.jvm.utility.analysis;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.Response;
import org.apache.catalina.connector.ResponseFacade;
import org.apache.commons.io.IOUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.ParameterNode;

public class ServletFinder {

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws IOException {
	String wsName = "SnipSnap";
	String jarPath = "/home/vladi/SnipSnap.jar";
	JarFile jarFile = new JarFile(jarPath);
	Collection<ServletInfo> mainServletClasses = getServletClasses(jarFile);
	jarFile.close();
	
	for (ServletInfo servletInfo : mainServletClasses) {
	    System.out.println(servletInfo);
	}
	
	System.out.println(generateEntryPoint(wsName, mainServletClasses));
    }
    
    private static String generateEntryPoint(String webServiceName, Collection<ServletInfo> servlets) {
	StringBuilder importsSB = new StringBuilder();
	
	importsSB.append("package webservice;\n\n");
	importsSB.append("import java.io.IOException;\n\n");
	importsSB.append("import javax.servlet.ServletException;\n\n");
	importsSB.append("import org.apache.catalina.connector.Request;\n");
	importsSB.append("import org.apache.catalina.connector.RequestFacade;\n");
	importsSB.append("import org.apache.catalina.connector.Response;\n");
	importsSB.append("import org.apache.catalina.connector.ResponseFacade;\n");
	
	StringBuilder classSB = new StringBuilder();
	classSB.append("public class " + webServiceName + "EntryPoint {\n");
	classSB.append("\n");
	classSB.append("\tpublic static void main(String[] args) throws IOException, ServletException {\n");
	classSB.append("\t\t\n");
	classSB.append("\t\tResponseFacade response = new ResponseFacade(new Response());\n");
	classSB.append("\t\tRequestFacade request = new RequestFacade(new Request());\n");
	classSB.append("\t\t\n");
	
	for (ServletInfo servlet : servlets) {
	    importsSB.append("import " + servlet.classFQName + ";\n");
	    String className = servlet.getClassName();
	    String varName = Character.toLowerCase(className.charAt(0)) + className.substring(1);
	    classSB.append("\t\t" + className + " " + varName + " = new " + className + "();\n");
	    if (servlet.hasDoGet) {
		classSB.append("\t\t" + varName + ".doGet(request, response);\n");
	    }
	    if (servlet.hasDoPost) {
		classSB.append("\t\t" + varName + ".doPost(request, response);\n");
	    }
	}
	
	classSB.append("\t}\n");
	classSB.append("\n");
	classSB.append("}");
	
	importsSB.append("\n\n\n");
	
	return importsSB.toString() + classSB.toString();
    }

    private static Set<ServletInfo> getServletClasses(JarFile jarFile) throws IOException {
	String jarName = jarFile.getName().substring(jarFile.getName().lastIndexOf(File.separatorChar) + 1,
		jarFile.getName().lastIndexOf('.'));
	Set<ServletInfo> mainServletClasses = new TreeSet<ServletInfo>();

	Enumeration<JarEntry> entryEnum = jarFile.entries();

	while (entryEnum.hasMoreElements()) {
	    JarEntry jarEntry = entryEnum.nextElement();
	    String name = jarEntry.getName();
	    if (name.endsWith(".class")) {
		ServletInfo servletInfo = checkJarEntry(jarFile.getInputStream(jarEntry));
		if (servletInfo != null) {
		    mainServletClasses.add(servletInfo);
		}

	    } else if (name.endsWith(".jar")) {
		// extract jarEntry
		BufferedInputStream jarIS = new BufferedInputStream(jarFile.getInputStream(jarEntry));
		File file = new File("/tmp/" + jarName + "/" + jarEntry.getName());
		file.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(file);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = jarIS.read(buffer)) > 0) {
		    fos.write(buffer, 0, len);
		}
		fos.close();
		jarIS.close();

		// recursively traverse
		if (file.exists()) {
		    mainServletClasses.addAll(getServletClasses(new JarFile(file)));
		}
	    }
	}

	return mainServletClasses;
    }

    private static ServletInfo checkJarEntry(InputStream entryInputStream) {
	try {
	    ClassReader cr = new ClassReader(entryInputStream);
	    ClassNode cn = new ClassNode();
	    cr.accept(cn, 0);

	    boolean hasDoGet = false, hasDoPost = false;

	    for (MethodNode methodNode : (List<MethodNode>) cn.methods) {
		// first check for params then for name
		Type retType = Type.getReturnType(methodNode.desc);
		Type[] paramTypes = Type.getArgumentTypes(methodNode.desc);
		if (retType.equals(Type.VOID_TYPE) && paramTypes.length == 2
			&& paramTypes[0].getClassName().equals(HttpServletRequest.class.getName())
			&& paramTypes[1].getClassName().equals(HttpServletResponse.class.getName())) {
		    if (methodNode.name.equals("doGet")) {
			hasDoGet = true;
		    } else if (methodNode.name.equals("doPost")) {
			hasDoPost = true;
		    }
		}
	    }
	    if (hasDoGet || hasDoPost) {
		ServletInfo servletInfo = new ServletInfo();
		servletInfo.classFQName = cn.name.replace("/", ".");
		servletInfo.hasDoGet = hasDoGet;
		servletInfo.hasDoPost = hasDoPost;
		return servletInfo;
	    }

	} catch (IOException e) {
	    e.printStackTrace();
	}
	return null;
    }
}
