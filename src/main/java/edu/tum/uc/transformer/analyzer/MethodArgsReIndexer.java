package edu.tum.uc.transformer.analyzer;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.LocalVariablesSorter;

import edu.tum.uc.tracker.MethodMetaInformation;
import edu.tum.uc.tracker.TaintTrackerConfig;

public class MethodArgsReIndexer extends MethodVisitor {

	private int[] args2NewArgsMapping;
	private int newArgsOffset;
	private boolean isStatic;
	private int argLastIndex;
	private MethodMetaInformation methodMetaInfo;
	
	public MethodArgsReIndexer(int api, MethodVisitor mv) {
		super(api, mv);
		// TODO Auto-generated constructor stub
	}

	public MethodArgsReIndexer(int api, MethodVisitor mv, MethodMetaInformation methodUtility) {
		this(api, mv);
		
		this.methodMetaInfo = methodUtility;
		this.args2NewArgsMapping = this.methodMetaInfo.getArgs2NewArgsMapping();
		this.newArgsOffset = this.methodMetaInfo.getNewArgsOffset();
		this.isStatic = this.methodMetaInfo.isStatic();
		this.argLastIndex = this.methodMetaInfo.getArgLastIndex();
	}

	@Override
	public void visitIincInsn(int var, int increment) {
		if (!this.isStatic && var == 0)
			var = 0;
		else if (var < this.argLastIndex) {
			//accessing an arg; remap it
			var = this.args2NewArgsMapping[var];// + (isStatic?0:1);
		} else {
			//not accessing an arg. just add offset.
			var += this.newArgsOffset;
		}
		super.visitIincInsn(var, increment);
	}

	public void visitVarInsn(int opcode, int var) {
//		if(opcode == TaintUtils.BRANCH_END || opcode == TaintUtils.BRANCH_START)
//		{
//			super.visitVarInsn(opcode, var);
//			return;
//		}
		int oriVar = var;
		if (!isStatic && var == 0)
			var = 0;
		else if (var < this.argLastIndex) {
			//accessing an arg; remap it
			var = this.args2NewArgsMapping[var];// + (isStatic?0:1);
		} else {
			//not accessing an arg. just add offset.
			var += this.newArgsOffset;
		}
        
//        store mapping from reindexed variable to original variable
		this.methodMetaInfo.getNewVar2Var().put(var, oriVar);
		
		super.visitVarInsn(opcode, var);
	}
	
	@Override
	public void visitLocalVariable(String name, String desc, String signature, Label start, Label end, int index) {
//		if (index < this.argLastIndex) {
//			boolean found = false;
//			for (Object _lv : lvStore.localVariables)
//			{
//				LocalVariableNode lv = (LocalVariableNode) _lv;
//				if (lv != null && lv.name != null && lv.name.equals(name) && lv.index == index)
//					found = true;
//			}
//			if (!found)
//				lvStore.localVariables.add(new LocalVariableNode(name, desc, signature, null, null, index));
//		}
		
		if (!isStatic && index == 0)
			super.visitLocalVariable(name, desc, signature, start, end, index);
		else if (index < this.argLastIndex) {
 			String shadow = TaintTrackerConfig.getShadowTaint(desc);
			String shadowVarName = TaintTrackerConfig.wrapLocalVariable(name);
			super.visitLocalVariable(name, desc, signature, start, end, this.args2NewArgsMapping[index]);
			if (shadow != null){
				Type descType = Type.getType(desc);
				super.visitLocalVariable(shadowVarName, shadow, null, start, end, this.args2NewArgsMapping[index]+descType.getSize());
			}
//			if(index == this.argLastIndex - 1 && Configuration.IMPLICIT_TRACKING)
//			{
//				super.visitLocalVariable("PhopshorImplicitTaintTrackingFromParent", Type.getDescriptor(ControlTaintTagStack.class), null, start, end, oldArgMappings[index]+1);
//			}
//			if (index == this.argLastIndex - 1 && this.name.equals("<init>") && hasTaintSentinalAddedToDesc) {
//				super.visitLocalVariable("TAINT_STUFF_TO_IGNORE_HAHA", "Ljava/lang/Object;", null, start, end, oldArgMappings[index] + (Configuration.IMPLICIT_TRACKING ? 2 : 1));
//			}
//			if ((index == this.argLastIndex - Type.getType(desc).getSize()) && hasPreAllocedReturnAddr) {
//				super.visitLocalVariable("PHOSPHORPREALLOCRETURNHAHA", newReturnType.getDescriptor(), null, start, end, oldArgMappings[index] + (Configuration.IMPLICIT_TRACKING ? 2 : 1));
//			}
		} else {
			super.visitLocalVariable(name, desc, signature, start, end, index + this.newArgsOffset);
		}
	}

	public void visitMethodInsn(int opcode, String owner, String name,
			String desc, boolean intf) {
		super.visitMethodInsn(opcode, owner, name, desc, intf);
	}

}
