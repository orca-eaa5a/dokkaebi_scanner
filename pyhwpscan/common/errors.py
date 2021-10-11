class ParsingError(Exception):
    def __str__(self):
        return "Parsing Error"

class OLEParsingError(Exception):
    def __str__(self):
        return "OLE Binary Parsing Error"

class FilsIsNotOLEBinaryError(OLEParsingError):
    def __str__(self):
        return "File is not a OLE Binary"

class StorageNotFoundError(OLEParsingError):
    def __str__(self):
        return "Storage is not in OLE Binary"

class StreamNotFoundError(OLEParsingError):
    def __str__(self):
        return "Stream is not in OLE Binary"

class HWPError(OLEParsingError):
    def __str__(self):
        return "HWP Error"

class FileIsNotHWPBinaryError(HWPError):
    def __str__(self):
        return "File is not a HWP Document"

class FileHasPasswordError(HWPError):
    def __str__(self):
        return "File has a password"
