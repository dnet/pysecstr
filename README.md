[![Build Status](https://travis-ci.com/VidaID/pysecbytes.svg?branch=master)](https://travis-ci.com/VidaID/pysecbytes)

## Install:

    pip install git+https://github.com/VidaID/pysecbytes.git  

## Use:

Currently supports clearing integers, strings and bytes

    from SecureBytes import clearmem, safemem
    
    x = b'data that must be removed'

    copy_of_x = x

    clearmem(x)

    assert(b'data' not in copy_of_x)

In python3 only, temporarily overriding mem allocator to zero ram and prevent paging:

    with safemem():
        x = b'data that must be removed'
        del x

    # x is not in ram

Currently, safemem and scanmem aren't supported on all pythons and platforms, 
use `import safemem_supported, scanmem_supported` to check.
    
## Warnings:

  - Do not try to derive from str or bytes... extra copies of your data will be made
  - Clearing strings and bytes also clears all references to them
  - If you choose store sensitive material in a class, and put clearmem in __del__, it will only be cleared when the last reference is freed
  - "safemem" is not yet efficient (TODO),  and it only prevents swapping on Windows (TODO)

