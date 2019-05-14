# This script decodes the strings of APT28's Zepakab.
# It assumes that the decoding function is named "hex_decode".
# It was written and tested for 3e713a838a68259ae2f9ef2eed05a761
# For a detailed analysis of APT28's Zepakab see
# https://www.vkremez.com/2019/01/lets-learn-overanalyzing-one-of-latest.html 

def find_deconding_function():
    """
    Finds the deconding function. The deconding function has
    to be manually named to 'hex_decode'. This function throws
    an exception if it does not find the deconding function.
    """
    for func in currentProgram.getFunctionManager().getFunctions(0x0):
        if func.getName() == 'hex_decode':
            return func
    raise Exception('Can not find deconding function')

def decode(offset):
    """
    Just convert the hex values to ASCII.
    """
    return getDataAt(offset).getValue().decode('hex')

def decode_xref(xref):
    """
    Extracts offset to next encoded string and decodes it.
    """
    callee = xref.getFromAddress()

    inst = getInstructionBefore(getInstructionAt(callee))
    if not 'MOV EAX' in inst.toString():
        print('[Warning] The instruction before is not MOV EAX')
        print('Called from %s' % callee)
        return None

    offset_hex = inst.getAddress(1)
    if not offset_hex:
        print('[Warning] Could not extract offset to encoded string')
        print('Called from %s' % callee)
        return None

    decoded_data = decode(offset_hex)
    return decoded_data

def add_comment(addr, comment):
    """
    Adds a comment to addr.
    """
    codeUnit = currentProgram.getListing().getCodeUnitAt(addr)
    codeUnit.setComment(codeUnit.EOL_COMMENT, comment)

def main():
    decoding_func_addr = find_deconding_function().getEntryPoint()
    print('Entry point of decoding function: %s' % str(decoding_func_addr))

    for xref in getReferencesTo(decoding_func_addr):
        s = decode_xref(xref)
        if s:
            # TODO patch the actual string value in the binary
            add_comment(xref.getFromAddress(), s)


main()

