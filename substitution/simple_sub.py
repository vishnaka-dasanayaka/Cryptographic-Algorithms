def encrypt(plaintext):
    char_set = {}
    for i in range(26):
        char_set[chr(97 + i)] = format(i, '07b')

    for i in range(26):
        char_set[chr(65 + i)] = format(i + 26, '07b')

    for i in range(10):
        char_set[chr(48 + i)] = format(i + 52, '07b')

    symbols = [' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>',
               '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~']

    for i, symbol in enumerate(symbols):
        char_set[symbol] = format(i + 62, '07b')

    # Initialize the ciphertext
    ciphertext = ""

    # Encrypt the plaintext
    for char in plaintext:
        if char in char_set:
            ciphertext += char_set[char]
        else:
            raise ValueError(f"Character '{char}' not supported in substitution encryption.")

    return ciphertext


def decrypt(cipher_text):
    char_set = {}

    for i in range(26):
        char_set[format(i, '07b')] = chr(97 + i)

    for i in range(26):
        char_set[format(i + 26, '07b')] = chr(65 + i)

    for i in range(10):
        char_set[format(i + 52, '07b')] = chr(48 + i)

    symbols = [
        ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
        ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'
    ]

    for i, symbol in enumerate(symbols):
        char_set[format(i + 62, '07b')] = symbol

    plain_text = ""

    for i in range(0, len(cipher_text), 7):
        binary_char = cipher_text[i:i + 7]
        if binary_char in char_set:
            plain_text += char_set[binary_char]
        else:
            raise ValueError(f"Not in the character set")

    return plain_text


plainText = input('Enter the message for encryption: ')

cipherText = encrypt(plainText)

print(f"Encrypted message: {cipherText}")

lengthOfCipher = len(cipherText)

print(f"count : {lengthOfCipher}")

print(f"Decrypted messeage : {decrypt(cipherText)}")