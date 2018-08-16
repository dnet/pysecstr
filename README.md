## Install:

    pip install git+https://github.com/VidaID/pysecbytes.git  

## Use:

    from SecureBytes import clearmem
    
    x = b'data that must be removed'

    copy_of_x = x

    clearmem(x)

    assert(b'data' not in copy_of_x)

    
## Warnings:

- Do not try to derive from str or bytes... extra copies of your data will be made
- Clearing strings and bytes also clears all references to them
- If you choose store sensitive material in a class, and put clearmem in __del__, it will only be cleared when the last reference is freed

