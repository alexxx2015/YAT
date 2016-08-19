package edu.tum.uc.tracker;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import edu.tum.uc.transformer.taint.TaintWrapper;

/**
 * Represents all meta information about a method. This includes the name,
 * signature, return type, description of the original as well as of the
 * extended method
 * 
 * @author alex
 *
 */
public class MethodMetaInformation {
	private int access;
	private String name;
	private String desc;
	private String signature;
	private String[] exceptions;
	private String classname;

	private Type[] argTypes;
	private Type returnType, newReturnType;
	LinkedList<Type> newArgTypes;
	private String newDesc;
//	stores argument mappings from the original to the new method signature
	private int[] args2NewArgsMapping;
//	maps mapped arguments to taints
	private Map<Integer, Integer> newArgs2TaintMapping;
//	maps original var to new var
	private Map<Integer,Integer> newVar2VarMapping;
	private int newArgsOffset;
	private boolean isStatic;
	private int argLastIndex;

	protected MethodMetaInformation(int access, String name, String desc, String signature, String[] exceptions,
			String classname) {
		this.access = access;
		this.name = name;
		this.desc = desc;
		this.signature = signature;
		this.exceptions = exceptions;
		this.classname = classname;
		
		this.newVar2VarMapping = new HashMap<Integer,Integer>();
		this.newArgs2TaintMapping = new HashMap<Integer, Integer>();

		init();
		computeArgsTaint();
	}

	// initialize method meta object
	private void init() {
		// pick to pieces method signature description
		this.argTypes = Type.getArgumentTypes(this.desc);
		this.newArgTypes = new LinkedList<Type>();
		for (Type t : this.argTypes) {
			this.newArgTypes.add(t);
			if(t.getSort() == Type.OBJECT && !TaintTrackerConfig.isString(t))
				continue;
//			determine proper taint for each argument and append it to newArgTypes
			if (t.getSort() == Type.ARRAY) {
				if (t.getElementType().getSort() != Type.OBJECT || TaintTrackerConfig.isString(t.getElementType())) {
					if (t.getDimensions() > 1) {
						this.newArgTypes.add(Type.getType(TaintTrackerConfig.TAINT_DESC));
					} else {
						this.newArgTypes.add(Type.getType(TaintTrackerConfig.TAINT_DESC_ARR));
					}
				}
			}
			else {
				this.newArgTypes.add(Type.getType(TaintTrackerConfig.TAINT_DESC));
			}
		}
		this.newReturnType = Type.getReturnType(desc);
		if (this.newReturnType.getSort() != Type.VOID && this.newReturnType.getSort() != Type.OBJECT) {
			TaintWrapper<?,?> returnType = TaintTrackerConfig.wrapReturnType(Type.getReturnType(desc));
			if(returnType != null)
				this.newReturnType = Type.getType(returnType.getClass());
		}
		else if( (this.newReturnType.getSort() == Type.OBJECT && TaintTrackerConfig.isString(this.newReturnType))
		|| (this.newReturnType.getSort() == Type.ARRAY && TaintTrackerConfig.isString(this.newReturnType.getElementType())) ){
			TaintWrapper<?,?> returnType = TaintTrackerConfig.wrapReturnType(Type.getReturnType(desc));
			if(returnType != null)
				this.newReturnType = Type.getType(returnType.getClass());
		}
		
		Type[] newArgs = new Type[newArgTypes.size()];
		newArgTypes.toArray(newArgs);
		this.newDesc = Type.getMethodDescriptor(newReturnType, newArgs);
	}

	// compute for each argument the corresponding taint marks
	private void computeArgsTaint() {
		this.isStatic = (Opcodes.ACC_STATIC & this.getAccess()) != 0;

		Type[] args = this.getArgTypes();

		// Compute the index of the last argument
		this.argLastIndex = this.isStatic ? 0 : 1;
		for (Type t : args) {
			this.argLastIndex += t.getSize();
		}

		// Remap method argument position
		this.newArgsOffset = 0;
		this.args2NewArgsMapping = new int[this.argLastIndex];
		int argCounter = this.isStatic ? 0 : 1;
		
		// newArgsOffset supports only 32-bit taint labels
		for (int i = 0; i < args.length; i++) {
//			maps original to new argument position
			this.args2NewArgsMapping[argCounter] = argCounter + this.newArgsOffset;
			if (this.args2NewArgsMapping[argCounter] < 0)	
				this.args2NewArgsMapping[argCounter] = 0;
			
//			map new argument position to its corresponding taint
			this.newArgs2TaintMapping.put(this.args2NewArgsMapping[argCounter], this.args2NewArgsMapping[argCounter] + args[i].getSize());
			argCounter += args[i].getSize();
			
			// every non-object array has a separated taint-label-array that
			// represents the taint value of each element
			if (args[i].getSort() == Type.ARRAY) {
				if (args[i].getElementType().getSort() != Type.OBJECT && args[i].getDimensions() == 1) {
					this.newArgsOffset++;
				}
				else if (args[i].getElementType().getSort() == Type.OBJECT && TaintTrackerConfig.isString(args[i].getElementType())){
					this.newArgsOffset++;
				}
			}
			// every primitive-typed parameter has an own taint-label
			else if (args[i].getSort() != Type.OBJECT || TaintTrackerConfig.isString(args[i])) {
				this.newArgsOffset++;
			}
		}
	}
	
	public Map<Integer,Integer> getNewVar2Var(){
		return this.newVar2VarMapping;
	}

	public String getMethodName() {
		return name;
	}

	public void setMethodName(String name) {
		this.name = name;
	}

	public String getDesc() {
		return desc;
	}

	public void setDesc(String desc) {
		this.desc = desc;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public String[] getExceptions() {
		return exceptions;
	}

	public void setExceptions(String[] exceptions) {
		this.exceptions = exceptions;
	}

	public Type[] getArgTypes() {
		return argTypes;
	}

	public void setArgTypes(Type[] argTypes) {
		this.argTypes = argTypes;
	}

	public Type getReturnType() {
		return returnType;
	}

	public void setReturnType(Type returnType) {
		this.returnType = returnType;
	}

	public Type getNewReturnType() {
		return newReturnType;
	}

	public void setNewReturnType(Type newReturnType) {
		this.newReturnType = newReturnType;
	}

	public LinkedList<Type> getNewArgTypes() {
		return newArgTypes;
	}

	public void setNewArgTypes(LinkedList<Type> newArgTypes) {
		this.newArgTypes = newArgTypes;
	}

	public String getNewDesc() {
		return newDesc;
	}

	public void setNewDesc(String newDesc) {
		this.newDesc = newDesc;
	}

	public String getClassName() {
		return classname;
	}

	public void setClassname(String classname) {
		this.classname = classname;
	}

	public int getAccess() {
		return access;
	}

	public void setAccess(int access) {
		this.access = access;
	}

	public int[] getArgs2NewArgsMapping() {
		return args2NewArgsMapping;
	}

	public void setArgsMapping(int[] argsMapping) {
		this.args2NewArgsMapping = argsMapping;
	}

	public int getNewArgsOffset() {
		return newArgsOffset;
	}

	public void setNewArgsOffset(int newArgsOffset) {
		this.newArgsOffset = newArgsOffset;
	}

	public boolean isStatic() {
		return isStatic;
	}

	public void setStatic(boolean isStatic) {
		this.isStatic = isStatic;
	}

	public int getArgLastIndex() {
		return argLastIndex;
	}

	public void setArgLastIndex(int argLastIndex) {
		this.argLastIndex = argLastIndex;
	}

	public Map<Integer, Integer> getArgs2TaintMapping() {
		return newArgs2TaintMapping;
	}

	public void setArgs2TaintMapping(Map<Integer, Integer> newArgs2TaintMapping) {
		this.newArgs2TaintMapping = newArgs2TaintMapping;
	}
}
