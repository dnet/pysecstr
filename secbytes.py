from  SecureBytes import clearmem

class secbytes(bytes):
    def __del__(self):
        clearmem(self)
