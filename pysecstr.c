#include <Python.h>
#include <openssl/crypto.h>
#include <stdio.h>

static PyObject* SecureString_clearmem(PyObject *self, PyObject *str) {
	char *buffer;
	Py_ssize_t length;

	if (PyString_AsStringAndSize(str, &buffer, &length) != -1) {
		OPENSSL_cleanse(buffer, length);
	}
	return Py_BuildValue("");
}

static PyMethodDef SecureStringMethods[] = {
	{"clearmem", SecureString_clearmem, METH_O,
		PyDoc_STR("clear the memory of the string")},
	{NULL, NULL, 0, NULL},
};

PyMODINIT_FUNC initSecureString(void)
{
	(void) Py_InitModule("SecureString", SecureStringMethods);
}
