#define PY_SSIZE_T_CLEAN

#include <Python.h>

#ifdef _WIN32
    #include <Windows.h>
    #include <vector>

    void _hexdump(char *dat, size_t len) {
        for (size_t i=0;i<len;++i) {
            printf("%02x", dat[i]);
        }
        printf("\n");
    }

    char* getAddressOfData(const char *a, size_t lena, const char *b, size_t lenb)
    {
        DWORD pid = GetCurrentProcessId();
        HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if(process)
        {
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            MEMORY_BASIC_INFORMATION info;
            std::vector<char> chunk;
            char* p = (char *)si.lpMinimumApplicationAddress;
            while(p < si.lpMaximumApplicationAddress)
            {
                if(VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info))
                {
                    p = (char*)info.BaseAddress;

                    const int chunk_size = 32768;
                    std::vector<char> chunk;
                    chunk.resize(chunk_size + lena + lenb);
                    //todo worry about boundry filling
                    char * chunk_ptr = chunk.data() + lena + lenb;
                    size_t remaining = info.RegionSize;

                    for (size_t offset = 0; offset < info.RegionSize; offset += chunk_size) {
                        SIZE_T bytesRead;
                        if(ReadProcessMemory(process, p+offset, chunk_ptr, remaining > chunk_size ? chunk_size : remaining, &bytesRead))
                        {
                            if (bytesRead < (lena+lenb))
                                continue;

                            for(size_t i = 0; i < (bytesRead - lena - lenb + 1); ++i)
                            {
                                if(memcmp(a, chunk_ptr+i, lena) == 0)
                                {
                                    if(memcmp(b, (chunk_ptr+i)+lena, lenb) == 0)
                                    {
                                        return (char*)p + i;
                                    }
                                }
                            }
                        } else {
                            break;
                        }
                        remaining -= chunk_size;
                    }
                    p += info.RegionSize;
                }
            }
        }
        return 0;
    }
#else
    char* getAddressOfData(const char *a, size_t lena, const char *b, size_t lenb) {
        // todo, some ptrace thing?  osx?
        return 0;
    }

#endif

static PyObject* SecureBytes_clearmem(PyObject *self, PyObject *args) {
    char *buffer;
    Py_ssize_t length;

    if(PyArg_ParseTuple(args, "s#", &buffer, &length)) {
        memset(buffer, 0, length);
        Py_RETURN_NONE;
    }
    PyErr_Clear();

    // support pylong
    PyLongObject *pyl;
    if(PyArg_ParseTuple(args, "O!", &PyLong_Type, &pyl)) {
        Py_ssize_t i = Py_SIZE(pyl);
        if (i < 0)
            i=-i;
        while (--i >= 0)
            pyl->ob_digit[i] = 0;
        Py_RETURN_NONE;
    }

    PyErr_SetString(PyExc_TypeError, "Argument must be a bytes-like object or an integer");

    return NULL;
}
static PyObject* SecureBytes_scanmem(PyObject *self, PyObject *args) {
    char *bufa;
    Py_ssize_t lena;
    char *bufb;
    Py_ssize_t lenb;

    if(!PyArg_ParseTuple(args, "s#s#", &bufa, &lena, &bufb, &lenb)) {
        return NULL;
    }
    if (getAddressOfData(bufa, lena, bufb, lenb)) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyMethodDef SecureBytesMethods[] = {
    {"clearmem", SecureBytes_clearmem, METH_VARARGS, PyDoc_STR("clear the memory of the string")},
    {"scanmem", SecureBytes_scanmem, METH_VARARGS, PyDoc_STR("scan memory of a process for a string")},
    {NULL, NULL, 0, NULL},
};

#if PY_MAJOR_VERSION >= 3
    static struct PyModuleDef SecureBytesDef = {
        PyModuleDef_HEAD_INIT,
        "SecureBytes",
        NULL,
        -1,
        SecureBytesMethods,
    };
	PyMODINIT_FUNC PyInit_SecureBytes(void) {
		return PyModule_Create(&SecureBytesDef);
	}
#else
	PyMODINIT_FUNC initSecureBytes(void)
	{
		(void) Py_InitModule("SecureBytes", SecureBytesMethods);
	}
#endif
