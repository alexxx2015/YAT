package edu.tum.uc.tracker;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import edu.tum.uc.jvm.utility.analysis.SinkSourceSpecReader;
import edu.tum.uc.transformer.taint.TaintWrapper;

public class TaintTrackerConfig {
	private static Logger _logger = Logger.getLogger(TaintTrackerConfig.class.getName());

	public static String CONFIG_FILE = "tracker.properties";
	public static final String CONFIG_SINKSOURCEFILE = "sinkSourceFile";
	public static final String CONFIG_TRACKINGTYPE = "trackingType";
	public static final String CONFIG_TAGSIZE = "tagSize";
	public static final String CONFIG_TRACKINGPRECISION = "trackingPrecision";
	public static final String CONFIG_TRACKINGCOVERAGE = "trackingCoverage";
	public static final String CONFIG_WHITELIST = "whitelist";
	private static Properties CONFIG;
	private static List<String[]> WHITELIST;

	// Taint tag's data type
	public static final String TAINT_DESC = "I";
	public static final String TAINT_WRAPPER_CLASS = TaintTrackerConfig.unescapeStr(Integer.class.getName());
	public static final String TAINT_WRAPPER_CLASS_METHOD = "intValue";
	public static final String TAINT_WRAPPER_CLASS_METHOD_DESC = "()I";
	public static final int TAINT_LOAD_INSTR = Opcodes.ILOAD;
	public static final int TAINT_LOAD_ARR_INSTR = Opcodes.ALOAD;
	public static final int TAINT_STORE_INSTR = Opcodes.ISTORE;
	public static final int TAINT_STORE_ARR_INSTR = Opcodes.ASTORE;
	public static final String TAINT_DESC_ARR = "[I";
	public static final String TAINT_MULTI_TAINT = "Ledu/tum/uc/tracker/taint/MultiTaint;";
	public static final String TAINT_ID = "__";
	public static final String TAINT_INSTANCEMARK = wrapWithTaintId("TAINT_INSTANCEMARK");
	public static boolean MULTI_TAINT_TRACKING = false;
	public static final int RAW_INSN = 201;
	public static final int EMPTY_TAINT = Opcodes.ICONST_0;
	public static final Integer[] EMPTY_ARR_TAINT = new Integer[32];
	public static final Object TAINT_STACK_TYPE = Opcodes.INTEGER;
	public static final String TAINT_STACK_ARR_TYPE = TAINT_DESC_ARR;

	public static SinkSourceSpecReader reader;

	public static int[] unbox(Integer[] p) {
		int[] _return = new int[p.length];
		int i = 0;
		for (Integer value : p) {
			_return[i++] = value.intValue();
		}
		return _return;
	}

	public static Integer[] box(int[] p) {
		Integer[] _return = new Integer[p.length];
		int i = 0;
		for (int u : p) {
			_return[i++] = new Integer(u);
		}
		return _return;
	}

	public static double[] unbox(Double[] p) {
		double[] _return = new double[p.length];
		int i = 0;
		for (Double value : p)
			_return[i++] = value.intValue();
		return _return;
	}

	public static Double[] box(double[] p) {
		Double[] _return = new Double[p.length];
		int i = 0;
		for (double u : p)
			_return[i++] = new Double(u);
		return _return;
	}

	public static String getProperty(String property) {
		String _return = null;
		// read CONFIG_FILE first
		if (CONFIG == null) {
			String configFile = CONFIG_FILE;
			if (!configFile.startsWith("/"))
				configFile = "/" + CONFIG_FILE;
			URL file = TaintTrackerConfig.class.getResource(configFile);
			if (file != null) {
				try {
					final FileInputStream fis = new FileInputStream(file.getPath());
					CONFIG = new Properties();
					CONFIG.loadFromXML(fis);
					fis.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else {
				_logger.error("Config-file " + configFile + " not found!");
			}
		}
		_return = CONFIG.getProperty(property);
		return _return;
		// TaintTrackerConfig.readSinkSourceSpec(file.getFile());
	}

	public static String wrapWithTaintId(String s) {
		return TAINT_ID + s + TAINT_ID;
	}

	public static String wrapLocalVariable(String... i) {
		String s = String.join("_", i);
		return wrapWithTaintId("SHADOWVAR_" + s);
	}

	public static String wrapLocalTmpVar(String... i) {
		String s = String.join("_", i);
		return wrapWithTaintId("TMPVAR_" + s);
	}

	public static String escapeStr(String str) {
		return str.replace("/", ".");
	}

	public static String unescapeStr(String str) {
		return str.replace(".", "/");
	}

	public static String makeBCSignature(String str) {
		if (str.length() == 1)
			return str;
		else if (str.length() > 0 && str.startsWith("["))
			return str;
		else if (str.length() > 0 && str.startsWith("L"))
			return str;
		return "L" + str + ";";
	}

	public static String makeBCSignature(Type t) {
		if (t.getSort() == Type.ARRAY) {
			return t.getDescriptor();
		} else {
			return makeBCSignature(t.getDescriptor());
		}
	}

	public static String getShadowTaint(String desc) {
		Type t = Type.getType(desc);
		if (t.getSort() == Type.OBJECT || t.getSort() == Type.VOID)
			return null;
		if (t.getSort() == Type.ARRAY && t.getDimensions() > 1)
			return null;
		if (t.getSort() == Type.ARRAY && t.getElementType().getSort() != Type.OBJECT)
			return TaintTrackerConfig.TAINT_DESC_ARR;
		if (t.getSort() == Type.ARRAY)
			return null;
		return TaintTrackerConfig.TAINT_DESC;
	}

	public static TaintWrapper<?, ?> wrapReturnType(Type t) {
		TaintWrapper<?, ?> helperTaintWrapper = null;

		// check for Strings
		if (TaintTrackerConfig.isString(t)) {
			return helperTaintWrapper = TaintWrapper.getWrapper("", TaintTrackerConfig.EMPTY_TAINT);
		}

		switch (t.getSort()) {
		case Type.BYTE:
			helperTaintWrapper = TaintWrapper.getWrapper((byte) 0, TaintTrackerConfig.EMPTY_TAINT);
			break;
		case Type.BOOLEAN:
			helperTaintWrapper = TaintWrapper.getWrapper(true, TaintTrackerConfig.EMPTY_TAINT);
			break;
		case Type.CHAR:
			helperTaintWrapper = TaintWrapper.getWrapper('a', TaintTrackerConfig.EMPTY_TAINT);
			break;
		case Type.SHORT:
			helperTaintWrapper = TaintWrapper.getWrapper((short) 0, TaintTrackerConfig.EMPTY_TAINT);
			break;
		case Type.DOUBLE:
			helperTaintWrapper = TaintWrapper.getWrapper(0.0, TaintTrackerConfig.EMPTY_TAINT);
			break;
		case Type.FLOAT:
			helperTaintWrapper = TaintWrapper.getWrapper(0.0f, TaintTrackerConfig.EMPTY_TAINT);
			break;
		case Type.INT:
			helperTaintWrapper = TaintWrapper.getWrapper(0, TaintTrackerConfig.EMPTY_TAINT);
			break;
		case Type.LONG:
			helperTaintWrapper = TaintWrapper.getWrapper(0L, TaintTrackerConfig.EMPTY_TAINT);
			break;
		case Type.ARRAY:
			// check for Strings arrays
			if (TaintTrackerConfig.isString(t.getElementType().getInternalName())) {
				helperTaintWrapper = TaintWrapper.getWrapper(new String[] {}, TaintTrackerConfig.EMPTY_ARR_TAINT);
				break;
			}

			switch (t.getElementType().getSort()) {
			case Type.BYTE:
				helperTaintWrapper = TaintWrapper.getWrapper(new Byte[] {}, TaintTrackerConfig.EMPTY_ARR_TAINT);
				break;
			case Type.BOOLEAN:
				helperTaintWrapper = TaintWrapper.getWrapper(new Boolean[] {}, TaintTrackerConfig.EMPTY_ARR_TAINT);
				break;
			case Type.CHAR:
				helperTaintWrapper = TaintWrapper.getWrapper(new Character[] {}, TaintTrackerConfig.EMPTY_ARR_TAINT);
				break;
			case Type.SHORT:
				helperTaintWrapper = TaintWrapper.getWrapper(new Short[] {}, TaintTrackerConfig.EMPTY_ARR_TAINT);
				break;
			case Type.DOUBLE:
				helperTaintWrapper = TaintWrapper.getWrapper(new Double[] {}, TaintTrackerConfig.EMPTY_ARR_TAINT);
				break;
			case Type.FLOAT:
				helperTaintWrapper = TaintWrapper.getWrapper(new Float[] {}, TaintTrackerConfig.EMPTY_ARR_TAINT);
				break;
			case Type.INT:
				helperTaintWrapper = TaintWrapper.getWrapper(new Integer[] {}, TaintTrackerConfig.EMPTY_ARR_TAINT);
				break;
			case Type.LONG:
				helperTaintWrapper = TaintWrapper.getWrapper(new Long[] {}, TaintTrackerConfig.EMPTY_ARR_TAINT);
				break;
			}
			break;
		}

		return helperTaintWrapper;
	}

	public static MethodMetaInformation createMethodUtilityObject(int access, String name, String desc,
			String signature, String[] exceptions, String classname) {
		return new MethodMetaInformation(access, name, desc, signature, exceptions, classname);
	}

	public static boolean isPrimitiveStackType(Object o) {
		boolean _return = false;

		if (o == Opcodes.INTEGER || o == Opcodes.FLOAT || o == Opcodes.DOUBLE || o == Opcodes.LONG || o == Opcodes.TOP)
			_return = true;

		return _return;
	}

	public static boolean isPrimitiveStackType(Type t) {
		boolean _return = false;
		switch (t.getSort()) {
		case Type.BOOLEAN:
		case Type.CHAR:
		case Type.BYTE:
		case Type.SHORT:
		case Type.INT:
		case Type.FLOAT:
		case Type.LONG:
		case Type.DOUBLE:
			_return = true;
		}
		return _return;
	}

	public static Type getPrimitiveWrapper(String desc) {
		Type t = Type.getReturnType(desc);
		Type _returnType = t;
		switch (t.getSort()) {
		case Type.BYTE:
			_returnType = Type.getType(Byte.class);
			break;
		case Type.SHORT:
			_returnType = Type.getType(Short.class);
			break;
		case Type.INT:
			_returnType = Type.getType(Integer.class);
			break;
		case Type.LONG:
			_returnType = Type.getType(Long.class);
			break;
		case Type.FLOAT:
			_returnType = Type.getType(Float.class);
			break;
		case Type.DOUBLE:
			_returnType = Type.getType(Double.class);
			break;
		case Type.BOOLEAN:
			_returnType = Type.getType(Boolean.class);
			break;
		case Type.CHAR:
			_returnType = Type.getType(Character.class);
			break;
		case Type.OBJECT:
			_returnType = t;
			break;
		}
		return _returnType;
	}

	public static void readSinkSourceSpec(String filename) {
		reader = new SinkSourceSpecReader();
		reader.readReport(filename);
	}

	private static int TaintMarkCounter = 5;
	private static Map<Object, Integer> TaintMap = new HashMap<Object, Integer>();

	public static int getTaint(String parentClassName, String parentMethodName, String childClassName,
			String childMethodName) {
		String key = TaintTrackerConfig.escapeStr(parentClassName) + "." + parentMethodName + "_"
				+ TaintTrackerConfig.escapeStr(childClassName) + "." + childMethodName;
		int _return = 0;
		// check if a taint label already exist
		if (TaintMap.containsKey(key)) {
			_return = TaintMap.get(key);
		}
		// generate a new taint label
		else {
			TaintMap.put(key, (_return = getNextTaint()));
		}
		return _return;
	}

	private static int getNextTaint() {
		int _return = TaintMarkCounter;
		TaintMarkCounter = TaintMarkCounter << 1;
		return _return;
	}

	// generates an array of taints
	public static int[] getTaint(int length) {
		int[] _return = new int[length];
		int taintMark = getNextTaint();
		for (int i = 0; i < _return.length; i++)
			_return[i] = taintMark;
		return _return;
	}

	// fills an array with the next taint label
	public static void getTaint(int[] arr) {
		if (!TaintMap.containsKey(arr)) {
			int nextTaint = getNextTaint();
			for (int i = 0; i < arr.length; i++) {
				arr[i] = nextTaint;
			}
			TaintMap.put(arr, nextTaint);
		}
	}

	public static boolean isString(Type type) {
		if (type.getSort() == Type.OBJECT)
			return isString(type.getInternalName());
		else if (type.getSort() == Type.ARRAY)
			return isString(type.getElementType());
		return false;
	}

	public static boolean isString(String className) {
		if (className.replace(".", "/").equals(String.class.getName().replace(".", "/")))
			return true;
		return false;
	}

	public static boolean isWhitelisted(Type t) {
		return isWhitelisted(t.getInternalName().replace("/", "."));
	}

	public static boolean isWhitelisted(String classname) {
		classname = TaintTrackerConfig.escapeStr(classname);
		boolean _return = false;
		// Read blacklist file if not done yet
		if (WHITELIST == null) {
			try {
				WHITELIST = new LinkedList<String[]>();
				String filename = getProperty(CONFIG_WHITELIST);
				if (!"".equals(filename)) {
					URL fileUrl = TaintTrackerConfig.class.getResource("/" + filename);
					File f = new File(fileUrl.getFile());
					FileInputStream fis = new FileInputStream(f);
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String line;
					while ((line = br.readLine()) != null) {
						String[] lineCmp = line.split(":");
						if (lineCmp.length == 2)
							WHITELIST.add(lineCmp);
					}
				}
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		if (WHITELIST.size() > 0) {
			Iterator<String[]> it = WHITELIST.iterator();
			while (it.hasNext()) {
				String[] cmp = it.next();
				switch (cmp[0]) {
				case "equals":
					if (classname.toLowerCase().equals(cmp[1].toLowerCase()))
						_return = true;
					break;
				case "contains":
					if (classname.toLowerCase().contains(cmp[1].toLowerCase()))
						_return = true;
					break;
				case "startswith":
					if (classname.toLowerCase().startsWith(cmp[1].toLowerCase()))
						_return = true;
					break;
				case "endswith":
					if (classname.toLowerCase().endsWith(cmp[1].toLowerCase()))
						_return = true;
					break;
				}
				if (_return)
					break;
			}
		}
		return _return;
	}

	public static boolean isMainMethod(int access, String name, String desc, String signature, String[] exceptions) {
		boolean _return = false;
		if (((access & Opcodes.ACC_STATIC) == Opcodes.ACC_STATIC) && "main".equals(name)
				&& "([Ljava/lang/String;)V".equals(desc)) {
			_return = true;
		}

		return _return;
	}
	
	public static boolean isMainMethod(int opcode, String owner, String name, String desc, boolean itf){
		boolean _return = false;
		if(opcode == Opcodes.INVOKESTATIC && "main".equals(name) && "([Ljava/lang/String;)V".equals(desc)){
			_return = true;
		}
		return _return;
	}

}
