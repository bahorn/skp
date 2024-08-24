"""
Generic PE things I needed
"""
import pefile

DE_SECURITY = 4

class PERemoveSig:
    def __init__(self, pedata):
        self._data = pedata
        self._pe = pefile.PE(data=self._data)

    def extract_sig(self):
        n_rva_sizes = self._pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

        if n_rva_sizes < DE_SECURITY:
            return None

        entry_security = \
            self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[DE_SECURITY]

        offset = entry_security.VirtualAddress
        size = entry_security.Size

        if size == 0:
            return None

        return (offset, size, self._data[offset:offset+size])

    def remove_sig(self):
        """
        return a copy of the data with the sig removed.

        just nulling out the directory.
        """
        res = self.extract_sig()
        if not res:
            return bytes(self._data)

        offset, size, _ = res

        data = bytearray(self._data)
        sig_offset = self._pe \
            .OPTIONAL_HEADER \
            .DATA_DIRECTORY[DE_SECURITY] \
            .__file_offset__
        data[sig_offset:sig_offset+8] = [0 for _ in range(8)]
        return bytes(data[:offset])


class PECheckSumFix:
    def __init__(self, input_data):
        self._pe_data = pefile.PE(data=input_data)

    def fix(self):
        # Need to zero it out first
        self._pe_data.OPTIONAL_HEADER.CheckSum = 0
        self._pe_data.OPTIONAL_HEADER.CheckSum = \
            self._pe_data.generate_checksum()
        return self._pe_data.write()
