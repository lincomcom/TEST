import base64

# from encrypted_fields import EncryptedTextField


# def encrypt_text(text):
#     return EncryptedTextField().get_prep_value(text)


# def decrypt_text(encrypted_text):
#     return EncryptedTextField().to_python(encrypted_text)


def string_to_base64(s):
    return base64.b64encode(s.encode()).decode()


def base64_to_string(b):
    return base64.b64decode(b.encode()).decode()

def main():
    password_str = 'qq123456'
    password_base64 = 'cXExMjM0NTY='
    
    print(f'string_to_base64 = {string_to_base64(password_str)}')
    print(f'base64_to_string = {base64_to_string(password_base64)}')

    return

if __name__ == '__main__':
    main()