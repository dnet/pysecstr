#define PY_SSIZE_T_CLEAN

#include <Python.h>

/*
static void _hexdump(char *dat, size_t len) {
    for (size_t i=0;i<len;++i) {
        printf("%02x", dat[i]);
    }
    printf("\n");
}
*/

#ifdef _WIN32
    #define MEMSCAN_SUPPORTED true

    #include <Windows.h>
    #include <vector>

   static char* getAddressOfData(const char *a, size_t lena, const char *b, size_t lenb)
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
#elif __linux__
    #define MEMSCAN_SUPPORTED check_memstats()

    #include <signal.h>
    #include <setjmp.h>
    #include <stdexcept>

    extern "C" {
    #include "memstats.h"
    }

    static jmp_buf jumpbuf;

    static bool check_memstats() {
        auto range = mem_stats(0);
        if (!range)
            return false;
        free_mem_stats(range);
        return true;
    }

	static void unblock_signal(int signum __attribute__((__unused__)))
	{
#ifdef _POSIX_VERSION
		sigset_t sigs;
		sigemptyset(&sigs);
		sigaddset(&sigs, signum);
		sigprocmask(SIG_UNBLOCK, &sigs, NULL);
#endif
	}

    void segfault_ignore(int sig)
    {
		unblock_signal(sig);
        longjmp(jumpbuf, 1);
    }

    sighandler_t suppress_segv() {
        return signal(SIGSEGV, segfault_ignore);
    }

    static char* getAddressOfData(const char *a, size_t lena, const char *b, size_t lenb) {
        auto range = mem_stats(0);
        if (!range)
            return 0;

        /* this is necessary because it's possible to read in memory information, and have it change
         * while you are executing.
         * there may be a linux api that works better (like the windows one above)
         */
        
        char *ret = NULL;
        while(!ret && range) {
            if (range->perms & PERMS_READ) {
            if (!strcmp(range->name,"[heap]") || !strcmp(range->name,"[stack]") || !strcmp(range->name,"")) {
                auto save = suppress_segv();
                if (setjmp(jumpbuf) == 0) {
                    for(size_t i = 0; i < (range->length - lena - lenb + 1); ++i)
                    {
                        if(memcmp(a, ((char *)range->start)+i, lena) == 0)
                        {
                            if(memcmp(b, (((char *)range->start)+i) + lena, lenb) == 0)
                            {
                                ret = ((char *)range->start)+i;
                                break;
                            }
                        }
                    }
                }
                signal(SIGSEGV, save);
            }
            }
            range = range->next;
        }

        free_mem_stats(range);
        return ret;
    }
#else
    static char* getAddressOfData(const char *a, size_t lena, const char *b, size_t lenb) {
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
#if PY_MAJOR_VERSION >= 3
    PyLongObject *pyl;
#else
    #if PY_MINOR_VERSION >= 7
        typedef PY_UINT32_T digit;
    #else
        typedef unsigned short digit;
    #endif
    struct {
        PyObject_VAR_HEAD
        digit ob_digit[1];
    } *pyl;
#endif

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

////////////////// safemem context
#if PY_VERSION_HEX >= 0x03000000
#define MEMALLOC
#endif

#if PY_VERSION_HEX >= 0x03050000
#  define PyMemAllocator PyMemAllocatorEx
#  define NEED_CALLOC
#endif

#ifdef MEMALLOC
#include <unordered_map>

class AllocMap {
    std::unordered_map<void *, size_t> map_;

    public:
        void * alloc(void *ptr, size_t size) {
#ifdef _WIN32
            VirtualLock(ptr, size);
#endif
            map_[ptr]=size;
            return ptr;
        }

        void free(void *ptr) {
            auto it = map_.find(ptr);
            if (it != map_.end())  {
                memset(ptr, 0, it->second);
                map_.erase(it);
            }
        }

        AllocMap() {
            setbuf(stdout, NULL);
        }
};

AllocMap map;

struct {
    PyMemAllocator obj;
} hook;

static void* hook_malloc(void *ctx, size_t size)
{
    PyMemAllocator *alloc = (PyMemAllocator *)ctx;
    return map.alloc(alloc->malloc(alloc->ctx, size), size);
}

static void* hook_realloc(void *ctx, void *ptr, size_t new_size)
{
    PyMemAllocator *alloc = (PyMemAllocator *)ctx;
    auto mem = alloc->realloc(alloc->ctx, ptr, new_size);
    map.free(ptr);
    map.alloc(mem, new_size);
    return mem;
}

#ifdef NEED_CALLOC
static void* hook_calloc(void *ctx, size_t nelem, size_t elsize)
{
    PyMemAllocator *alloc = (PyMemAllocator *)ctx;
    return map.alloc(alloc->calloc(alloc->ctx, nelem, elsize), nelem*elsize);
}
#endif


static void hook_free(void *ctx, void *ptr)
{
    PyMemAllocator *alloc = (PyMemAllocator *)ctx;
    map.free(ptr);
    alloc->free(alloc->ctx, ptr);
}

PyMemAllocator g_alloc;

static PyObject* pysafemem_start(PyObject *self, PyObject *args) {
    g_alloc.malloc = hook_malloc;
#ifdef NEED_CALLOC
    g_alloc.calloc = hook_calloc;
#endif
    g_alloc.realloc = hook_realloc;
    g_alloc.free = hook_free;

    PyMem_GetAllocator(PYMEM_DOMAIN_OBJ, &hook.obj);

    g_alloc.ctx = &hook.obj;
    PyMem_SetAllocator(PYMEM_DOMAIN_OBJ, &g_alloc);
    Py_RETURN_NONE;
}

static PyObject* pysafemem_stop(PyObject *self, PyObject *args) {
    PyMem_SetAllocator(PYMEM_DOMAIN_OBJ, &hook.obj);
    Py_RETURN_NONE;
}
#else
static PyObject* pysafemem_start(PyObject *self, PyObject *args) {
    Py_RETURN_NONE;
}

static PyObject* pysafemem_stop(PyObject *self, PyObject *args) {
    Py_RETURN_NONE;
}
#endif // memalloc

typedef struct {
    PyObject_HEAD
    /* Type-specific fields go here. */
} SafeCtxObj;

static PyMethodDef SafeCtx_methods[] = {
    {"start", pysafemem_start, METH_STATIC | METH_NOARGS, PyDoc_STR("begin using safe mem allocator")},
    {"stop", pysafemem_stop, METH_STATIC | METH_NOARGS, PyDoc_STR("end using safe mem allocator")},
    {"__enter__", pysafemem_start, METH_VARARGS, PyDoc_STR("begin using safe mem allocator")},
    {"__exit__", pysafemem_stop, METH_VARARGS, PyDoc_STR("end using safe mem allocator")},
    {NULL, NULL, 0, NULL},
};

static void
SafeCtx_dealloc(PyObject* self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
SafeCtx_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    return type->tp_alloc(type, 0);
}

static PyTypeObject SafeCtxType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "SecureBytes.safemem",
    sizeof(SafeCtxObj),
    0,
    (destructor)SafeCtx_dealloc,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    Py_TPFLAGS_DEFAULT,
    "pysafemem context object",
    0,0,0,0,0,0,
    SafeCtx_methods,
    0,0,0,0,0,0,0,0,0,
    SafeCtx_new,
};

static void pysafemem_init(PyObject*m) {
#ifdef MEMALLOC    
    PyModule_AddIntConstant(m, "safemem_supported", 1);
#else
    PyModule_AddIntConstant(m, "safemem_supported", 0);
#endif

    if (MEMSCAN_SUPPORTED) {
        PyModule_AddIntConstant(m, "scanmem_supported", 1);
    } else {
        PyModule_AddIntConstant(m, "scanmem_supported", 0);
    }

    if (PyType_Ready(&SafeCtxType) < 0)
        return;

    PyModule_AddObject(m, "safemem", (PyObject *) &SafeCtxType);
}

#if PY_MAJOR_VERSION >= 3
    static struct PyModuleDef SecureBytesDef = {
        PyModuleDef_HEAD_INIT,
        "SecureBytes",
        NULL,
        -1,
        SecureBytesMethods,
    };
	PyMODINIT_FUNC PyInit_SecureBytes(void) {
		auto m = PyModule_Create(&SecureBytesDef);
        pysafemem_init(m);
        return m;
	}
#else
	PyMODINIT_FUNC initSecureBytes(void)
	{
		auto m = Py_InitModule("SecureBytes", SecureBytesMethods);
        pysafemem_init(m);
	}
#endif
