package edu.tum.uc.transformer.archive;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.LocalVariablesSorter;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LocalVariableNode;

import edu.tum.uc.jvm.utility.analysis.Flow.Chop;
import edu.tum.uc.tracker.TaintTrackerConfig;

public class MethodTransformer2 extends MethodVisitor {
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
	
	private Map<Integer, LocalVariableNode> localVarToShadow;
	private Map<Integer, LocalVariableNode> localVarTmp;
	private Label endLabel;
	public LocalVariablesSorter lvs;

	public MethodTransformer2(int api) {
		super(api);
	}

	public MethodTransformer2(int api, MethodVisitor mv, int access,
			String name, String desc, String signature,
			String className, ClassVisitor cv,
			String superName, List<Chop> chopNodes) {
		super(api, mv);
		this.methodName = name;
		this.className = className;
		this.superName = superName;
		this.accessFlags = access;

		this.descriptor = desc;
		this.cv = cv;

		this.fqName = this.className.replace("/", ".") + "|" + this.methodName
				+ this.descriptor;
		this.chopNodes = chopNodes;
		this.endLabel = new Label();
		this.localVarToShadow = new HashMap<Integer, LocalVariableNode>();
		this.localVarTmp = new HashMap<Integer, LocalVariableNode>();
	}

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
		// System.out.println(this.className+"."+this.methodName+": "+Mnemonic.OPCODE[opcode]+", "+var);

		if (opcode == Opcodes.RETURN || opcode == Opcodes.RET) {
			mv.visitVarInsn(opcode, var);
			return;
		}

		int taintVarIndex = this.createShadowVar(opcode, var,
				Type.getType(TaintTrackerConfig.TAINT_DESC));
		int taintVarOpcode;
		if (opcode == Opcodes.ILOAD || opcode == Opcodes.DLOAD
				|| opcode == Opcodes.LLOAD || opcode == Opcodes.ALOAD
				|| opcode == Opcodes.FLOAD) {
			taintVarOpcode = TaintTrackerConfig.MULTI_TAINT_TRACKING ? Opcodes.ALOAD
					: Opcodes.ILOAD;
			mv.visitVarInsn(taintVarOpcode, taintVarIndex);// Push taint mark
															// on stack
			mv.visitVarInsn(opcode, var);// Push actual value on stack

		} else if (opcode == Opcodes.ISTORE || opcode == Opcodes.DSTORE
				|| opcode == Opcodes.LSTORE || opcode == Opcodes.ASTORE
				|| opcode == Opcodes.FSTORE) {
			taintVarOpcode = TaintTrackerConfig.MULTI_TAINT_TRACKING ? Opcodes.ASTORE
					: Opcodes.ISTORE;
			mv.visitVarInsn(opcode, var);// Push actual value on stack
			mv.visitVarInsn(taintVarOpcode, taintVarIndex);// Push taint mark
															// on stack

		} else {
			mv.visitVarInsn(opcode, var);
		}
	}
	
//	@Override
	public void visitInsn(int opcode){
		if(opcode == Opcodes.IADD){
			//Assuming T-V-T-V on stack
			int tmpVar = this.createTmpVar(Type.INT_TYPE);
			mv.visitVarInsn(Opcodes.ISTORE, tmpVar);
			//T-V-T
			mv.visitInsn(Opcodes.SWAP);
			//T-T-V
			mv.visitVarInsn(Opcodes.ILOAD, tmpVar);
			//T-T-V-V
			mv.visitInsn(opcode);
			//T-T-V
			mv.visitInsn(Opcodes.DUP_X2);
			//V-T-T-V
			mv.visitInsn(Opcodes.POP);
			//V-T-T
			mv.visitInsn(Opcodes.IOR);
			//V-T
			mv.visitInsn(Opcodes.SWAP);
			//T-V
		}else{
			mv.visitInsn(opcode);
		}
	}

	private int createShadowVar(int opcode, int var, Type type) {
		int index = -1;
		LocalVariableNode shadowLocVar;
		if (this.localVarToShadow.containsKey(var)) {
			shadowLocVar = this.localVarToShadow.get(var);
			index = shadowLocVar.index;
		} else {
			index = this.lvs.newLocal(type);
			String locVarName = TaintTrackerConfig.wrapLocalVariable(String
					.valueOf(var));
			Label startLabel = new Label();
			mv.visitLabel(startLabel);
			shadowLocVar = new LocalVariableNode(locVarName,
					type.getDescriptor(), null, new LabelNode(startLabel),
					new LabelNode(this.endLabel), index);
			this.localVarToShadow.put(var, shadowLocVar);
		}
		return index;
	}

	private int createTmpVar(Type type) {
		int index = -1;
		index = this.lvs.newLocal(type);
		String locVarName = TaintTrackerConfig.wrapLocalTmpVar(String
				.valueOf(index));
		Label startLabel = new Label();
		mv.visitLabel(startLabel);
		LocalVariableNode tmpLocVar = new LocalVariableNode(locVarName,
				type.getDescriptor(), null, new LabelNode(startLabel),
				new LabelNode(endLabel), index);
		this.localVarTmp.put(index, tmpLocVar);
		return index;
	}

	@Override
	public void visitEnd() {
		if (this.localVarToShadow.size() > 0) {
			for (int key : this.localVarToShadow.keySet()) {
				LocalVariableNode n = this.localVarToShadow.get(key);
				mv.visitLocalVariable(n.name, n.desc, n.signature,
						n.start.getLabel(), n.end.getLabel(), n.index);
			}
			this.localVarToShadow.clear();
		}
		if(this.localVarTmp.size() > 0){
			for (int key : this.localVarTmp.keySet()) {
				LocalVariableNode n = this.localVarTmp.get(key);
				mv.visitLocalVariable(n.name, n.desc, n.signature,
						n.start.getLabel(), n.end.getLabel(), n.index);
			}
			this.localVarTmp.clear();
		}
		mv.visitLabel(endLabel);
		mv.visitEnd();
	}
	
	public void setLvs(LocalVariablesSorter lvs){
		this.lvs = lvs;
	}
	
	public LocalVariablesSorter getLvs(){
		return this.lvs;
	}
}
