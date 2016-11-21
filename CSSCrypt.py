"""
Clyde's Simple Shuffler Encryption

@Desc
This encryption algorthym is design for users to use their own keys to build
a unique encrypted output. It called shuffler as it uses the inputed key
to shuffle each character in the message, thus making it harder to crack.

I highly advise you to not use this for passwords. Paswords are secured by
hashing and not through encryption. Hashed values can't be decrypted where as
encryption can. Feel free to encrypt stuff for fun and use this as a learning
tool.

If you use this to encrypt something sensitive, use at your own discretion. I am
not responsible for messages you've created that's gotten cracked.

@author
Clyde Smets <clyde.smets@gmail.com>

@license
MIT

"""
import re
from pathlib import Path

class encryption:

    # Character values within the list is used to encode the message.
    # Default file 'key/encoding.txt' uses base64, change it to whatever.
    __encodingValues = []

    # Pad identifier. Padding is used in encoding to fit the bit block size
    __pad = ''

    # The bit size helps determine the encoding index value by x num of binary
    # bits. For example base64 is 6 - it grabs 6 bits to create a decimal for
    # assigning that index value to a charater. 010011 => 15 => T
    # The default value is assigned at the top of the file 'key/encoding.txt'
    __bitSize = 0

    def __init__ (self):
        
        # Check if encoding file exists
        encodingFilePath = 'key/encoding.txt'
        encodingFile = Path(encodingFilePath)
        
        if encodingFile.is_file():
            lines = self.__readByLine(encodingFilePath)
            self.__encodingValues = lines[1:-1]
            self.__bitSize = int(lines[0])
            self.__pad = lines[-1]
            
        else:
            raise Exception('encoding.txt is not found')


    def encrypt (self, message, key):

        # Encode the message
        encoded = self.__encode(message)

        # count number of encoding pads
        padNum = encoded.count(self.__pad)

        # remove and store the encoding padded values
        pads = encoded[-padNum:]
        encoded = encoded[:-padNum]    

        # Extend the key to cover the length of the encoding values
        key = self.__resize(key, len(encoded))

        encrypted = ''

        # Shift the encoded values according to the key.
        # Values can only shift from 0-9.
        for i in range(len(encoded)):
            shift = self.__shift(encoded[i], int(key[i]))
            encrypted = encrypted + shift

        # reattached padding to the encrypted output
        encrypted = encrypted + pads

        return encrypted 


    def decrypt (self, encrypted, key):

        # Resize the key to the length of the encrypted message
        key = self.__resize(key, len(encrypted))

        # Count number of encoding pads
        padNum = encrypted.count(self.__pad)

        # Remove and store the encoding padded values
        pads = encrypted[-padNum:]
        encrypted = encrypted[:-padNum]  

        decrypted = ''

        # unshift the encrypted message to be decoded using the key.
        for i in range(len(encrypted)):
            unshift = self.__unshift(encrypted[i], int(key[i]))
            decrypted = decrypted + unshift

        # re-append the padding
        decrypted = decrypted + pads

        # decode the message and return the decrypted result.
        decoded = self.__decode(decrypted)

        return decoded


    # Resize the length of a string to match the amount.
    def __resize (self, string, amount):
        
        if len(string) < amount:
            index = 0
            for i in range(len(string), amount):
                string = string + string[index]
                index = index + 1

        elif len(string) > amount: # if it's larger cut it
            cutAmount = amount - len(string) # negative value
            string = string[:cutAmount]

        return string
        

    def __encode (self, message):

        encoded = ''
        longBinary = ''

        # Loop through characters in message to convert it to binary
        for i in range(len(message)):

            # Convert to hexadecimal
            hexChar = format(ord(message[i]), "x")
            
            # Convert hexadecimal to decimal
            decimal = int(hexChar, 16)

            # Convert decimal to binary
            binary = '{0:08b}'.format(decimal)
            
            longBinary += binary

        # Encoding requires 24 bit blocks. So the long binary has to be split
        # into bits of 24. If a block doesn't complete 24 bits, pad it!
        # so that it does. e.g. '100110110101' => '100110110101000000000000'
        blockSize = 24
        blocks = []
        counter = 0
        block = ''

        # build the blocks
        for i in range(len(longBinary)):

            if longBinary[i]:
                if counter < blockSize:
                    block += longBinary[i]
                    counter = counter + 1
                else:
                    counter = 0
                    blocks.append(block)
                    block = longBinary[i]

        # append last remaining block if it has values
        if len(block) > 0:
            blocks.append(block)

        # pad the last block
        for i in range(len(blocks)):

            if len(blocks[i]) < blockSize:

                # append padded 0
                size = blockSize - len(blocks[i])
                for b in range(size):

                    blocks[i] = blocks[i] + '0'

        # convert back to long binary
        longBinary = ''.join(blocks)

        # group binary values by bit size
        grouped =  self.__groupBinary(longBinary, self.__bitSize)


        # Get the encoded character for the binary group. But it will
        # require the binary to be converted to decimal to find the index
        # position.

        # Find the number of groups that is required to make a block
        numOfGroups = blockSize // self.__bitSize

        # Loop through, except for the last group. Since we also know that to
        # create a group it needs at least one group of bits, thus we can forget
        # that one (i.e. numOfGroups - 1)
        for gi in range(len(grouped) - (numOfGroups - 1)):

            eDecimal = int(grouped[gi], 2)

            encoded += self.__encodingValues[eDecimal]

        # Size of padding
        padding = ''
        for n in range(self.__bitSize):
            padding += '0'

        # Check to see the last remaining groups are padded, and if they are,
        # assign them a padded value.
        for lgi in range(numOfGroups - 1):

            target = len(grouped) - (3 - lgi)

            if grouped[target] == padding:
                encoded += self.__pad

            else:
                eDecimal = int(grouped[target], 2)
                encoded += self.__encodingValues[eDecimal]

        return encoded


    def __decode (self, message):

        decoded = ''
        longBinary = ''
        pads = ''
        
        # Size of padding
        padding = ''
        for n in range(self.__bitSize):
            padding += '0'

        # Loop through encoded message and return values as binary
        for i in range(len(message)):

            # Find position of char in index
            index = 0

            # Find the index values from the encoding key
            for mi in range(len(self.__encodingValues)):

                if message[i] == self.__encodingValues[mi]:
                    index = mi
                    break

            # Check if the character is a padding value or not
            if message[i] == self.__pad:
                pads += padding
                break

            # Convert index to binary following bit amount
            binaryFormat = '{0:0' + str(self.__bitSize) + 'b}'
            binary = binaryFormat.format(index)

            longBinary += binary

        # Append padding to converted indexes
        longBinary = longBinary + pads


        # group binary values to divisable of 8
        grouped =  self.__groupBinary(longBinary, 8)

        # Decode
        for i in range(len(grouped)):

            # Get decimal from binary
            decimal = int(grouped[i], 2)

            # Get hexadecimal from decimal
            hexadecimal = hex(decimal).split('x')[1]

            # Get character from hex
            if (hexadecimal != '0'):  
                char = bytes.fromhex(hexadecimal).decode('utf-8')

                decoded += char

        return decoded


    # Write to content to file
    def __write (self, file, contents):

        f = open(file, 'w')
        f.write(contents)
        f.closed()


    # Read a file line by line and return it as a list
    def __readByLine (self, file):
        
        contents = []
        
        with open(file) as line:
            contents = line.read().splitlines()

        return contents
    

    # Return a list of binary values grouped by bit size
    def __groupBinary (self, binary, bitSize):
        
        # group binary values by base number
        grouped =  re.findall('.{1,' + str(bitSize) + '}', binary)

        # Fill the last value with any missing 0 - so groups are whole
        # e.g. '01' will be changed to '000001' if bit size is 6
        lastGroupSize = len(grouped[len(grouped) - 1])
        
        if lastGroupSize < bitSize:

            count = 0

            amount = bitSize - lastGroupSize

            while count < amount:
                grouped[len(grouped) - 1] = '0' + grouped[len(grouped) - 1]
                count = count + 1

        return grouped


    # Find the character in the list and find it's shifted value
    def __shift (self, char, amount):

        values = self.__encodingValues

        index = self.__charPosition(char, values)

        shift = index + amount
        if shift < len(values):
            return values[shift]
        else:
            remainder = len(self.__encodingValues) - (index + 1)
            shift = (amount - remainder) - 1
            return values[shift]
            

    # Getting the original value unshifted value.
    def __unshift (self, char, amount):

        values = self.__encodingValues

        index = self.__charPosition(char, values)

        return values[index - amount]


    # Return the index value of a matching character in a long string.
    def __charPosition (self, char, string):

        index = 0

        # Get the index value of the character in the list
        for i in range(len(string)):
            if string[i] == char:
                index = i
                break

        return index

