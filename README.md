## Install:

    pip install git+https://github.com/VidaID/pysecbytes.git  

## Use:

    from SecureBytes import clearmem
    
    x = b'data that must be removed'

    copy_of_x = x

    clearmem(x)

    assert(b'data' not in copy_of_x)

    


