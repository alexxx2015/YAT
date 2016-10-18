package edu.tum.uc.transformer;

import java.lang.reflect.Method;
import java.util.LinkedList;
import java.util.List;

import edu.tum.uc.tracker.TaintTrackerConfig;

/**
 * This class handles special cases at runtime for reflective calls
 * 
 * @author alex
 *
 */
public class ReflectionHandler {

	/**
	 * creates for a new method object base on the provided method @m. The new
	 * method signature is adapted an populated with taint variables
	 * 
	 * @param m
	 * @return
	 */
	public static Method adaptMethod(Method m) {
		Method _return = m;
		String mName = m.getName();
		Class<?> mClass = m.getDeclaringClass();

		List<Class<?>> newParams = new LinkedList<Class<?>>();
		for (Class<?> c : m.getParameterTypes()) {
			newParams.add(c);
			if (c.isPrimitive()) {
				newParams.add(TaintTrackerConfig.TAINT_DESC_CLASS);
			} else if (TaintTrackerConfig.isString(c.getName())) {
				newParams.add(TaintTrackerConfig.TAINT_DESC_CLASS);
			} else if (c.isArray() && TaintTrackerConfig.isString(c.getName())) {
				newParams.add(TaintTrackerConfig.TAINT_DESC_CLASS);
			}
		}

		try {
			Class<?>[] mParams = newParams.toArray(new Class<?>[0]);
			_return = mClass.getMethod(mName, mParams);
		} catch (NoSuchMethodException | SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return _return;
	}

	public static Class<?>[] adaptMethodSignature(Class<?>[] params) {
		List<Class<?>> _return = new LinkedList<Class<?>>();
		for (Class<?> c : params) {
			_return.add(c);
			if (c.isPrimitive()) {
				_return.add(TaintTrackerConfig.TAINT_DESC_CLASS);
			} else if (TaintTrackerConfig.isString(c.getName())) {
				_return.add(TaintTrackerConfig.TAINT_DESC_CLASS);
			} else if (c.isArray() && TaintTrackerConfig.isString(c.getName())) {
				_return.add(TaintTrackerConfig.TAINT_DESC_CLASS);
			}
		}
		Class<?>[] r = _return.toArray(new Class<?>[0]);
		return r;
	}

	public static Object[] adaptMethodParameters(Object[] params) {
		List<Object> _return = new LinkedList<Object>();
		for (Object o : params) {
			_return.add(o);
			_return.add(new Integer(0));
		}
		return _return.toArray(new Object[0]);
	}

}
