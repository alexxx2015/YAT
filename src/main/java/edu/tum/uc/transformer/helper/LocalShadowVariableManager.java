package edu.tum.uc.transformer.helper;

import java.util.HashMap;
import java.util.Map;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.LocalVariablesSorter;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LocalVariableNode;

import edu.tum.uc.tracker.TaintTrackerConfig;

public class LocalShadowVariableManager extends LocalVariablesSorter {

	private String classsname;
	private String methodname;
	private Label endLabel;

	private Map<Integer, LocalVariableNode> localVarToShadow;

	protected LocalShadowVariableManager(int api, int access, String desc,
			MethodVisitor mv) {
		super(api, access, desc, mv);
	}

	public LocalShadowVariableManager(int access, String desc,
			MethodVisitor mv, String classname, String methodname) {
		super(Opcodes.ASM5, access, desc, mv);
		this.classsname = classname;
		this.methodname = methodname;
		this.localVarToShadow = new HashMap<Integer, LocalVariableNode>();
		this.endLabel = new Label();
	}

	public int createShadowVar(int opcode, int var, Type type) {
		if (this.methodname.toLowerCase().contains("init") && var == 6) {
			int a = 5;
			a++;
		}
		
		int index = -1;
		LocalVariableNode shadowLocVar;
		if(this.localVarToShadow.containsKey(var)){
			shadowLocVar = this.localVarToShadow.get(var);
			index = shadowLocVar.index;
		}
		else{
		index = super.newLocal(type);
		String locVarName = TaintTrackerConfig.wrapLocalVariable(String.valueOf(var));
		Label startLabel = new Label();
		mv.visitLabel(startLabel);
		shadowLocVar = new LocalVariableNode(locVarName,
				type.getDescriptor(), null, new LabelNode(startLabel),
				new LabelNode(this.endLabel), index);
		this.localVarToShadow.put(var, shadowLocVar);
		}
		return index;
	}	
	
	@Override
	public void visitLocalVariable(String name, String desc, String signature, Label start, Label end, int index) {
		mv.visitLocalVariable(name, desc, signature, start, end, index);
	}
	public void visitEnd(){
		if (this.localVarToShadow.size() > 0) {
			for (int key: this.localVarToShadow.keySet()) {
				LocalVariableNode n = this.localVarToShadow.get(key);
				mv.visitLocalVariable(n.name, n.desc, n.signature, n.start.getLabel(), n.end.getLabel(), n.index);
			}
			this.localVarToShadow.clear();
		}
		mv.visitLabel(endLabel);
		mv.visitEnd();
	}

}
