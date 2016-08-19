package edu.tum.uc.transformer;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.net.URL;
import java.security.ProtectionDomain;

import org.apache.log4j.Logger;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.util.TraceClassVisitor;

import edu.tum.uc.tomcat.TomcatClassLoader;
import edu.tum.uc.tracker.TaintTrackerConfig;


public class MainTransformer implements ClassFileTransformer {
	private static Logger _logger = Logger.getLogger(MainTransformer.class.getName());

	private static TomcatClassLoader myClassLoader;

	private static ProtectionDomain myProtDom;
	
	private boolean instrument_webservice;
	
	public MainTransformer(){this(null);_logger.info("No properties file found or specified for tracker");}
	public MainTransformer(String configFile){		
		if(configFile != null) TaintTrackerConfig.CONFIG_FILE = configFile;
		
		String sinkSourceFile = TaintTrackerConfig.getProperty(TaintTrackerConfig.CONFIG_SINKSOURCEFILE);
		if(sinkSourceFile != null){
			URL url = this.getClass().getResource("/"+sinkSourceFile);
			TaintTrackerConfig.readSinkSourceSpec(url.getFile());
		}
	}

	public byte[] transform(ClassLoader loader, String className,
			Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
			byte[] classfileBuffer) throws IllegalClassFormatException {
		if(!TaintTrackerConfig.isWhitelisted(className)) return classfileBuffer;
		
		//System.out.println("[MyUcTransformer]: Calling tranform ...");
		if (this.instrument_webservice) {
			this.setClassLoader(loader);
			this.setProtectionDomain(protectionDomain);
		}
		
//		Read to analyze class
		ClassReader cr = new ClassReader(classfileBuffer);
		
//		Create classnode as described in the ASM's tree-api 
//		ClassNode cn = new ClassNode();
//		cr.accept(cn, 0);

		//Use a custom classwriter, that uses internally a special classloader for webservices
		ClassWriter cw = new MyClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
//		CheckClassAdapter cca = new CheckClassAdapter(cw);
//		trace and prints complete class on std-out
//		PrintWriter pw = new PrintWriter(new NullOutputStream());
		PrintWriter pw = new PrintWriter(System.out);
		TraceClassVisitor tcv = new TraceClassVisitor(cw,pw);

		ClassVisitor cv = new ClassTransformer(Opcodes.ASM5, cw, cr.getClassName());
//		ClassVisitor cv = new ClassTransformer(Opcodes.ASM5, tcv, cr.getClassName());
		cr.accept(cv, ClassReader.EXPAND_FRAMES);
		return cw.toByteArray();
	}
	
	private void setClassLoader(ClassLoader p_myClassLoader) {
		MainTransformer.myClassLoader = (TomcatClassLoader) p_myClassLoader;
	}

	public static ClassLoader getMyClassLoader() {
		return MainTransformer.myClassLoader;
	}

	private void setProtectionDomain(ProtectionDomain p_protectionDomain) {
		MainTransformer.myProtDom = p_protectionDomain;
	}

}
