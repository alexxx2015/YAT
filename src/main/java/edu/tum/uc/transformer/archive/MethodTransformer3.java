package edu.tum.uc.transformer.archive;

import java.util.List;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.MethodNode;

import edu.tum.uc.jvm.utility.analysis.Flow.Chop;
import edu.tum.uc.tracker.TaintTrackerConfig;
import edu.tum.uc.transformer.helper.LocalShadowVariableManager;

public class MethodTransformer3 extends MethodVisitor {

	/**
	 * The method name.
	 */
	private String methodName;
	/**
	 * The name of the class this method belongs to.
	 */
	private String className;
	private String superName;
	/**
	 * The access flags of the method.
	 */
	private int accessFlags;
	/**
	 * The fully qualified name of this method consisting of the class and
	 * method names and the descriptor.
	 */
	private String fqName;
	/**
	 * The descriptor of the method.
	 */
	private String descriptor;
	/**
	 * The list of chop nodes being located in this method.
	 */
	private List<Chop> chopNodes;
	/**
	 * The class writer being the end of the class-as-event-chain-processing.
	 */
	private ClassVisitor cv;
	/**
	 * Determines if Information Flow Tracking should be instrumented or not.
	 * */
	private boolean ift = true;

	/**
	 * A local variable manager for each method transformation
	 */
	private LocalShadowVariableManager lvm;
	private MethodNode methodNode;

	protected MethodTransformer3(int p_api, MethodVisitor p_mv, int p_access,
			String p_name, String p_desc, String p_signature,
			String p_className, List<Chop> p_chopNodes, ClassVisitor cv,
			String p_superName, MethodNode methodNode) {
		super(p_api, p_mv);

		this.methodName = p_name;
		this.className = p_className;
		this.superName = p_superName;
		this.accessFlags = p_access;

		this.descriptor = p_desc;
		this.cv = cv;

		this.fqName = this.className.replace("/", ".") + "|" + this.methodName
				+ this.descriptor;
		this.chopNodes = p_chopNodes;

		if (mv instanceof LocalShadowVariableManager) {
			this.lvm = (LocalShadowVariableManager) mv;
		} 
//		else {
//			lvm = new LocalShadowVariableManager(p_access, p_desc, mv,
//					TaintTrackerConfig.escapeStr(this.className),
//					TaintTrackerConfig.escapeStr(p_name));
//		}

		// this.ift = Boolean.parseBoolean(ConfigProperties
		// .getProperty(ConfigProperties.PROPERTIES.IFT));
	}
	
	public MethodTransformer3(int arg0) {
		super(arg0);
		// TODO Auto-generated constructor stub
	}
	
	protected void setLvs(LocalShadowVariableManager lvs){
		this.lvm = lvs;
	}
	
	protected LocalShadowVariableManager getLvs(){
		return this.lvm;
	}

	@Override
	public void visitCode() {
		// System.out.println("Class "+this.className+";"+this.methodName+", visitCode()");
		mv.visitCode();
	}

	@Override
	public void visitFieldInsn(int opcode, String owner, String name,
			String desc) {
		Type t = Type.getType(desc);
		String taintDesc = (t.getSort() == Type.ARRAY) ? TaintTrackerConfig.TAINT_DESC_ARR
				: TaintTrackerConfig.TAINT_DESC;
		// System.out.println("FIELDINS: "+Mnemonic.OPCODE[opcode]+", "+owner+", "+name);
		if (opcode == Opcodes.GETFIELD) {
			mv.visitFieldInsn(opcode, owner,
					TaintTrackerConfig.wrapWithTaintId(name), taintDesc);
			mv.visitInsn(Opcodes.POP);
			mv.visitFieldInsn(opcode, owner, name, desc);
		} else if (opcode == Opcodes.PUTFIELD) {
			mv.visitFieldInsn(opcode, owner, name, desc);
			mv.visitFieldInsn(opcode, owner,
					TaintTrackerConfig.wrapWithTaintId(name), taintDesc);
		} else {
			mv.visitFieldInsn(opcode, owner, name, desc);
		}
	}

	public void visitVarInsn(int opcode, int var) {
//		System.out.println(this.className+"."+this.methodName+": "+Mnemonic.OPCODE[opcode]+", "+var);
		
		if(opcode == Opcodes.RETURN || opcode == Opcodes.RET){
			mv.visitVarInsn(opcode, var);
			return;
		}
		
		int taintVarIndex = this.lvm.createShadowVar(opcode, var,
				Type.getType(TaintTrackerConfig.TAINT_DESC));
		int taintVarOpcode;
		if (opcode == Opcodes.ILOAD || opcode == Opcodes.DLOAD
				|| opcode == Opcodes.LLOAD || opcode == Opcodes.ALOAD
				|| opcode == Opcodes.FLOAD) {
			taintVarOpcode = TaintTrackerConfig.MULTI_TAINT_TRACKING ? Opcodes.ALOAD
					: Opcodes.ILOAD;
			mv.visitVarInsn(taintVarOpcode, taintVarIndex);
			mv.visitVarInsn(opcode, var);

		} else if (opcode == Opcodes.ISTORE || opcode == Opcodes.DSTORE
				|| opcode == Opcodes.LSTORE || opcode == Opcodes.ASTORE
				|| opcode == Opcodes.FSTORE) {
			taintVarOpcode = TaintTrackerConfig.MULTI_TAINT_TRACKING ? Opcodes.ASTORE
					: Opcodes.ISTORE;
			mv.visitVarInsn(opcode, var);
			mv.visitVarInsn(taintVarOpcode, taintVarIndex);

		} else {
			mv.visitVarInsn(opcode, var);
		}
	}
	
	@Override
	public void visitInsn(int opcode){
		if(opcode == Opcodes.IADD){
		}
		mv.visitInsn(opcode);
	}

	// public void visitLocalVariable(String name, String desc, String
	// signature, Label start, Label end, int index) {
	// this.lvm.visitLocalVariable(name, desc, signature, start, end, index);
	// }
//	public void visitEnd() {
//		this.lvm.visitEnd();
//	}
//	@Override
//	public void visitMaxs(int maxStack, int maxLocals) {
//		mv.visitMaxs(maxStack, maxLocals);
//	}

}
