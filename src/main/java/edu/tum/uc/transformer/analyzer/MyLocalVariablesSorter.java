package edu.tum.uc.transformer.analyzer;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.LocalVariablesSorter;
import org.objectweb.asm.tree.LocalVariableNode;

import edu.tum.uc.tracker.MethodMetaInformation;
import edu.tum.uc.tracker.TaintTrackerConfig;
import edu.tum.uc.transformer.MethodTransformer;

public class MyLocalVariablesSorter extends LocalVariablesSorter {
	private static final Type OBJECT_TYPE = Type.getObjectType("java/lang/Object");

	private MethodMetaInformation methodMetaInfo;
	private MethodTransformer methodTransformer;

	public MyLocalVariablesSorter(int version, int access, String desc, MethodVisitor mv, MethodMetaInformation mmi,
			MethodTransformer methodTransformer) {
		super(version, access, desc, mv);
		this.methodMetaInfo = mmi;
		this.methodTransformer = methodTransformer;
	}

	@Override
	public void visitFrame(final int type, final int nLocal, final Object[] local, final int nStack,
			final Object[] stack) {

		// retrieve newLocals-attribute and required methods from super class
		Object[] newLocals = null;
		Method mSetFrameLocal = null, mRemap = null;
		try {
			Field[] fields = this.getClass().getSuperclass().getDeclaredFields();
			for (Field f : fields) {
				if (f.getName().toLowerCase().equals("newlocals")) {
					f.setAccessible(true);
					newLocals = (Object[]) f.get(this);
					break;
				}
			}

			Method[] methods = this.getClass().getSuperclass().getDeclaredMethods();
			for (Method m : methods) {
				if ("setframelocal".equals(m.getName().toLowerCase())) {
					m.setAccessible(true);
					mSetFrameLocal = m;
				} else if ("remap".equals(m.getName().toLowerCase())) {
					m.setAccessible(true);
					mRemap = m;
				}
			}
		} catch (IllegalArgumentException | IllegalAccessException e) {
		}

		if (type != Opcodes.F_NEW) { // uncompressed frame
			throw new IllegalStateException("ClassReader.accept() should be called with EXPAND_FRAMES flag");
		}

		// creates a copy of newLocals
		Object[] oldLocals = new Object[newLocals.length];
		System.arraycopy(newLocals, 0, oldLocals, 0, oldLocals.length);

		updateNewLocals(newLocals);

		// required to resolve mapping between arguments
		int[] args2NewArgsMap = this.methodMetaInfo.getArgs2NewArgsMapping();
		Map<Integer, Integer> args2TaintMap = this.methodMetaInfo.getArgs2TaintMapping();
		Map<Integer, Integer> var2VarMap = this.methodMetaInfo.getNewVar2Var();

		// copies types from 'local' to 'newLocals'
		// 'newLocals' already contains the variables added with 'newLocal'
		int index = 0; // old local variable index
		int number = 0; // old local variable number
		for (; number < nLocal; ++number) {
			Object t = local[number];
			int size = t == Opcodes.LONG || t == Opcodes.DOUBLE ? 2 : 1;
			if (t != Opcodes.TOP) {
				Type typ = OBJECT_TYPE;
				if (t == Opcodes.INTEGER) {
					typ = Type.INT_TYPE;
				} else if (t == Opcodes.FLOAT) {
					typ = Type.FLOAT_TYPE;
				} else if (t == Opcodes.LONG) {
					typ = Type.LONG_TYPE;
				} else if (t == Opcodes.DOUBLE) {
					typ = Type.DOUBLE_TYPE;
				} else if (t instanceof String) {
					typ = Type.getObjectType((String) t);
				}
				if (mSetFrameLocal != null && mRemap != null) {
					// setFrameLocal(remap(index, typ), t);
					try {
						// figure out to which mapped variable this
						// local-variable belongs to
						int newIndex = index;
						if (index < this.methodMetaInfo.getArgLastIndex() && args2NewArgsMap.length >= index) {
							newIndex = args2NewArgsMap[index];
						} else {
							Iterator<Integer> it = var2VarMap.keySet().iterator();
							while (it.hasNext()) {
								int next = it.next();
								if (var2VarMap.get(next) == index) {
									newIndex = next;
									break;
								}
							}
						}
						mSetFrameLocal.invoke(this, mRemap.invoke(this, newIndex, typ), t);
						// mSetFrameLocal.invoke(this, mRemap.invoke(this,
						// index,typ),t);

						boolean addTaint = true;
						if (typ.getSort() == Type.OBJECT && !TaintTrackerConfig.isString(typ)) {
							addTaint = false;
						} else if (typ.getSort() == Type.ARRAY && !TaintTrackerConfig.isString(typ.getElementType())) {
							addTaint = false;
						}
						// add taint-information to stack frame
						if (addTaint) {
							// check if local variable is a method argument
							if (index < this.methodMetaInfo.getArgLastIndex() && args2NewArgsMap.length > index) {
								int taintIndex = args2TaintMap.containsKey(newIndex) ? args2TaintMap.get(newIndex) : -1;
								if (taintIndex > 0) {
									// Taint tag stack type
									Object taintIndexType = TaintTrackerConfig.TAINT_STACK_TYPE;
									if (typ.getSort() == Type.ARRAY) {
										taintIndexType = TaintTrackerConfig.TAINT_STACK_ARR_TYPE;
									}
									mSetFrameLocal.invoke(this, taintIndex, taintIndexType);
								}
							}
							// otherwise it must be a local variable
							else {
								LocalVariableNode lvn = this.methodTransformer.getLocalVar2Shadow().containsKey(
										newIndex) ? this.methodTransformer.getLocalVar2Shadow().get(newIndex) : null;
								if (lvn != null) {
									int taintIndex = lvn.index;
									Object taintIndexType = TaintTrackerConfig.TAINT_STACK_TYPE;
									if (typ.getSort() == Type.ARRAY) {
										taintIndexType = TaintTrackerConfig.TAINT_STACK_ARR_TYPE;
									}
									mSetFrameLocal.invoke(this, taintIndex, taintIndexType);
								}
							}
						}
					} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
			index += size;
		}

		// removes TOP after long and double types as well as trailing TOPs

		index = 0;
		number = 0;
		for (int i = 0; index < newLocals.length; ++i) {
			Object t = newLocals[index++];
			if (t != null && t != Opcodes.TOP) {
				newLocals[i] = t;
				number = i + 1;
				if (t == Opcodes.LONG || t == Opcodes.DOUBLE) {
					index += 1;
				}
			} else {
				newLocals[i] = Opcodes.TOP;
			}
		}

		// visits remapped frame
		mv.visitFrame(type, number, newLocals, nStack, stack);

		// restores original value of 'newLocals'
		newLocals = oldLocals;
	}
}
