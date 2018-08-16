#define PY_SSIZE_T_CLEAN

#include <Python.h>

#ifdef _WIN32
    #include <Windows.h>
    #include <vector>
    char* getAddressOfData(const char *data, size_t len)
    {
        DWORD pid = GetCurrentProcessId();
        HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if(process)
        {
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            MEMORY_BASIC_INFORMATION info;
            std::vector<char> chunk;
            char* p = 0;
            while(p < si.lpMaximumApplicationAddress)
            {
                if(VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info))
                {
                    p = (char*)info.BaseAddress;
                    chunk.resize(info.RegionSize);
                    SIZE_T bytesRead;
                    if(ReadProcessMemory(process, p, &chunk[0], info.RegionSize, &bytesRead))
                    {
                        for(size_t i = 0; i < (bytesRead - len); ++i)
                        {
                            if(memcmp(data, &chunk[i], len) == 0)
                            {
                                return (char*)p + i;
                            }
                        }
                    }
                    p += info.RegionSize;
                }
            }
        }
        return 0;
    }
#else
    char* getAddressOfData(const char *data, size_t len) {
        // todo, some ptrace thing?  osx?
        return 0;
    }

#endif

#if PY_MAJOR_VERSION >= 3
	static PyObject* SecureBytes_clearmem(PyObject *self, PyObject *args) {
		char *buffer;
		Py_ssize_t length;

		if(!PyArg_ParseTuple(args, "s#", &buffer, &length)) {
			return NULL;
		}
		memset(buffer, 0, length);
		Py_RETURN_NONE;
	}
	static PyObject* SecureBytes_scanmem(PyObject *self, PyObject *args) {
		char *buffer;
		Py_ssize_t length;

		if(!PyArg_ParseTuple(args, "s#", &buffer, &length)) {
			return NULL;
		}
		if (getAddressOfData(buffer, length)) {
            Py_RETURN_TRUE;
        }
        Py_RETURN_FALSE;
	}
#else
	static PyObject* SecureBytes_clearmem(PyObject *self, PyObject *str) {
		char *buffer;
		Py_ssize_t length;

		if (PyString_AsStringAndSize(str, &buffer, &length) != -1) {
		    memset(buffer, 0, length);
		}
		Py_RETURN_NONE;
	}
#endif

#if PY_MAJOR_VERSION >= 3
	static PyMethodDef SecureBytesMethods[] = {
		{"clearmem", SecureBytes_clearmem, METH_VARARGS, "clear the memory of a bytes-like object or string"},
		{"scanmem", SecureBytes_scanmem, METH_VARARGS, "scan process memory for a bytes-like object or string"},
		{NULL, NULL, 0, NULL},
	};
#else
	static PyMethodDef SecureBytesMethods[] = {
		{"clearmem", SecureBytes_clearmem, METH_O,
		PyDoc_STR("clear the memory of the string")},
		{NULL, NULL, 0, NULL},
	};
#endif

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef SecureBytesDef = {
	PyModuleDef_HEAD_INIT,
	"SecureBytes",
	NULL,
	-1,
	SecureBytesMethods,
};
#endif

#if PY_MAJOR_VERSION >= 3
	PyMODINIT_FUNC PyInit_SecureBytes(void) {
		return PyModule_Create(&SecureBytesDef);
	}
#else
	PyMODINIT_FUNC initSecureBytes(void)
	{
		(void) Py_InitModule("SecureBytes", SecureBytesMethods);
	}
#endif
