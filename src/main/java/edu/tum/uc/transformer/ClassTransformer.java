package edu.tum.uc.transformer;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AnalyzerAdapter;
import org.objectweb.asm.commons.LocalVariablesSorter;
import org.objectweb.asm.tree.ClassNode;

import edu.tum.uc.jvm.utility.analysis.Flow.Chop;
import edu.tum.uc.tracker.MethodMetaInformation;
import edu.tum.uc.tracker.TaintTrackerConfig;
import edu.tum.uc.transformer.analyzer.MethodArgsReIndexer;
import edu.tum.uc.transformer.analyzer.MyLocalVariablesSorter;
import edu.tum.uc.transformer.archive.MethodTransformer2;

/**
 * This class is responsible to provide a MethodVisitor object to ASM in order
 * to instrument a method.
 * 
 * @author Alexander Fromm
 *
 */
public class ClassTransformer extends ClassVisitor {
	/**
	 * The name of the class.
	 */
	private String className;
	private ClassNode cn;

	private int version;
	private int access;
	private String name;
	private String signature;
	private String[] interfaces;
	private String superName;

	// stores methods, espially wrapper-methods, that have been added to the
	// class
	private final Map<String, String> addedMethods = new HashMap<String, String>();

	// a simple counter that provides a unique value that is appended to the
	// wrapper method names
	private int methodId = 0;

	public ClassTransformer(int p_api, ClassVisitor p_cv, String classname) {
		super(p_api, p_cv);
		this.className = TaintTrackerConfig.escapeStr(classname);
	}

	public ClassTransformer(int p_api, ClassVisitor p_cv, ClassNode cn) {
		super(p_api, p_cv);
		this.cn = cn;
		this.className = this.cn.name;
	}

	// returns a map of methods that were added to that class
	public Map<String, String> getAddedMethods() {
		return this.addedMethods;
	}

	public int genNewMethodId() {
		return this.methodId++;
	}

	/**
	 * Visits a method of the class.
	 * 
	 * @param p_access
	 *            The method's acccess flags.
	 * @param p_name
	 *            The method name.
	 * @param p_desc
	 *            The descriptor of the method.
	 * @param p_signature
	 *            The signature of the method.
	 * @param p_exceptions
	 *            The internal names of the method's exception classes.
	 */
	// @Override
	public MethodVisitor _visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
		List<Chop> chopNodes = new LinkedList<Chop>();
		MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
		if ((access & Opcodes.ACC_NATIVE) != Opcodes.ACC_NATIVE) {
			// if (!isInterface && mv != null && !name.equals("<init>")) {
			MethodTransformer2 at = new MethodTransformer2(Opcodes.ASM5, mv, access, name, desc, signature,
					this.className, cv, this.superName, chopNodes);
			// at.aa = new AnalyzerAdapter(this.className, access, name, desc,
			// at);
			at.setLvs(new LocalVariablesSorter(access, desc, at));
			mv = at.getLvs();
		}
		return mv;
		// }
	}

	@Override
	public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
		this.version = version;
		this.access = access;
		this.name = name;
		this.signature = signature;
		this.superName = superName;
		this.interfaces = interfaces;
		cv.visit(version, access, name, signature, superName, interfaces);
	}

	@Override
	public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
		return cv.visitAnnotation(desc, visible);
	}

	@Override
	public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {
		Type fieldType = Type.getType(desc);

		// no shadow taint variable for whitelisted objects, because they have a
		// special taint mark attribute
		// non-whitelised objects are stored inside the RuntimeTracker class
		if (fieldType.getSort() == Type.OBJECT && !TaintTrackerConfig.isString(fieldType)) {
			return cv.visitField(access, name, desc, signature, value);
		} else if (fieldType.getSort() == Type.ARRAY && fieldType.getElementType().getSort() == Type.OBJECT){
//				&& fieldType.getElementType().getSort() != Type.ARRAY) {
			return cv.visitField(access, name, desc, signature, value);
		}

		// add a shadow field for each original field in that class
		int taintAccess = access & ~Opcodes.ACC_FINAL & ~Opcodes.ACC_PRIVATE & ~Opcodes.ACC_PROTECTED;
		taintAccess = taintAccess | Opcodes.ACC_PUBLIC;
		String taintDesc = (fieldType.getSort() == Type.ARRAY) ? TaintTrackerConfig.TAINT_DESC_ARR
				: TaintTrackerConfig.TAINT_DESC;
		// add shadow field
		cv.visitField(taintAccess, TaintTrackerConfig.wrapWithTaintId(name), taintDesc, null, 0);
		return cv.visitField(access, name, desc, signature, value);
	}

	// Add a taint mark for the whole class
	@Override
	public void visitEnd() {
		// add a special taint mark for the whole object
		int fieldAcc = Opcodes.ACC_PUBLIC;
		if ((this.access & Opcodes.ACC_INTERFACE) == Opcodes.ACC_INTERFACE){
			fieldAcc |= Opcodes.ACC_STATIC;
			fieldAcc |= Opcodes.ACC_FINAL;
		}
		cv.visitField(fieldAcc, TaintTrackerConfig.TAINT_INSTANCEMARK, TaintTrackerConfig.TAINT_DESC, null, 0);
		cv.visitEnd();
	}

	// add method visitor which add taint propagation logic into each single
	// method
	public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
		// Generate new method signature that also includes the different
		// taint marks
		MethodMetaInformation methodUtility = TaintTrackerConfig.createMethodUtilityObject(access, name, desc,
				signature, exceptions, this.className);

		// do not modify main-method signature
		if (!TaintTrackerConfig.isMainMethod(access, name, desc, signature, exceptions)) {
			desc = methodUtility.getNewDesc();
		}

		// Forward the method to next ClassVisitor in chain
		MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
		// If the method is not native, switch in the instrumenting
		// MyMethodVisitor
		// We cannot instrument native machine code
		if ((access & Opcodes.ACC_NATIVE) != Opcodes.ACC_NATIVE) {
			// mv = new AnalyzerAdapter(this.className, access, name, desc, mv);

			mv = new MethodTransformer(Opcodes.ASM5, mv, methodUtility, cv, this.superName, this);
			MethodTransformer methTrans = (MethodTransformer) mv;

			// simulates operations on stack- and localVariable-table
			AnalyzerAdapter analyzerAdapter = new AnalyzerAdapter(this.className, access, name, desc, methTrans);

			// creates and maintains local variable entries
			MyLocalVariablesSorter lvs = new MyLocalVariablesSorter(Opcodes.ASM5, access, desc, analyzerAdapter,
					methodUtility, methTrans);

			// Reindex method arguments
			MethodArgsReIndexer mArgsReIdx = new MethodArgsReIndexer(Opcodes.ASM5, lvs, methodUtility);

			// AnalyzerAdapter restructure method frames
			// NeverNullArgAnalyzerAdapter neverNullAnalyzer = new
			// NeverNullArgAnalyzerAdapter(
			// this.className, access, name, desc, mArgsReIdx);
			methTrans.setAnalyzerAdapter(analyzerAdapter);
			methTrans.setLvs(lvs);
			mv = mArgsReIdx;
		}
		return mv;
	}

}
