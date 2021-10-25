#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <openssl/crypto.h>

static PyObject* SecureString_clearmem(PyObject *self, PyObject *args) {
	char *buffer;
	Py_ssize_t length;

	if(!PyArg_ParseTuple(args, "s#", &buffer, &length)) {
		return NULL;
	}
	OPENSSL_cleanse(buffer, length);
	return Py_BuildValue("");
}

static PyMethodDef SecureStringMethods[] = {
	{"clearmem", SecureString_clearmem, METH_VARARGS, "clear the memory of the string"},
	{NULL, NULL, 0, NULL},
};

static struct PyModuleDef SecureStringDef = {
	PyModuleDef_HEAD_INIT,
	"SecureString",
	NULL,
	-1,
	SecureStringMethods,
};

PyMODINIT_FUNC PyInit_SecureString(void) {
	return PyModule_Create(&SecureStringDef);
}
