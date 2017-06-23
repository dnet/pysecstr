#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <openssl/crypto.h>

#if PY_MAJOR_VERSION >= 3
	static PyObject* SecureString_clearmem(PyObject *self, PyObject *args) {
		char *buffer;
		Py_ssize_t length;

		if(!PyArg_ParseTuple(args, "s#", &buffer, &length)) {
			return NULL;
		}
		OPENSSL_cleanse(buffer, length);
		return Py_BuildValue("");
	}
#else
	static PyObject* SecureString_clearmem(PyObject *self, PyObject *str) {
		char *buffer;
		Py_ssize_t length;

		if (PyString_AsStringAndSize(str, &buffer, &length) != -1) {
			OPENSSL_cleanse(buffer, length);
		}
		return Py_BuildValue("");
	}
#endif

#if PY_MAJOR_VERSION >= 3
	static PyMethodDef SecureStringMethods[] = {
		{"clearmem", SecureString_clearmem, METH_VARARGS, "clear the memory of the string"},
		{NULL, NULL, 0, NULL},
	};
#else
	static PyMethodDef SecureStringMethods[] = {
		{"clearmem", SecureString_clearmem, METH_O,
		PyDoc_STR("clear the memory of the string")},
		{NULL, NULL, 0, NULL},
	};
#endif

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef SecureStringDef = {
	PyModuleDef_HEAD_INIT,
	"SecureString",
	NULL,
	-1,
	SecureStringMethods,
};
#endif

#if PY_MAJOR_VERSION >= 3
	PyMODINIT_FUNC PyInit_SecureString(void) {
		return PyModule_Create(&SecureStringDef);
	}
#else
	PyMODINIT_FUNC initSecureString(void)
	{
		(void) Py_InitModule("SecureString", SecureStringMethods);
	}
#endif