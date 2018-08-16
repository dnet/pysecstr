from  SecureBytes import clearmem

class secbytes(bytes):
    def __del__():
        clearmem(this)
