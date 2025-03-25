import hashlib

def crack_sha1_hash(hash, use_salts=False):
    # Load the list of passwords from the file
    with open('top-10000-passwords.txt', 'r') as password_file:
        passwords = password_file.read().splitlines()
    
    # If using salts, load salts from the file
    salts = []
    if use_salts:
        with open('known-salts.txt', 'r') as salt_file:
            salts = salt_file.read().splitlines()
    
    # Iterate through passwords
    for password in passwords:
        # If no salts, hash the password directly
        if not use_salts:
            hashed_password = hashlib.sha1(password.encode()).hexdigest()
            if hashed_password == hash:
                return password
        else:
            # If salts are used, hash the password with each salt
            for salt in salts:
                # Prepend salt
                hashed_password = hashlib.sha1((salt + password).encode()).hexdigest()
                if hashed_password == hash:
                    return password
                # Append salt
                hashed_password = hashlib.sha1((password + salt).encode()).hexdigest()
                if hashed_password == hash:
                    return password
    
    # If no match is found, return this message
    return "PASSWORD NOT IN DATABASE"
