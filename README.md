# Mustafa's Password Hasher v1.0
==========================================

## A Python Script for Generating Password Hashes

### Overview
Mustafa's Password Hasher is a Python script that generates various password hashes, including MD5, SHA-1, SHA-256, and NTLM. This script is designed to be a simple and easy-to-use tool for generating password hashes, and is intended for educational purposes only.

### Features

* Generates four different types of password hashes:
	+ MD5 (Message-Digest Algorithm 5)
	+ SHA-1 (Secure Hash Algorithm 1)
	+ SHA-256 (Secure Hash Algorithm 256)
	+ NTLM (NT LAN Manager) hash, also known as the MD4 hash of the UTF-16 little-endian encoded password
* Uses secure password input with `getpass`
* Easy to use and understand

### Usage

#### TO install the requirements 

`pip install -r requirements.txt`

#### Example :
`Note : <-- The password is Hidden --> `
`Here the password is pass as example`
<hr>
#### Enter password to hash :

#### Hashes ===>

##### MD5
<=== MD5 ===>  
`1a1dc91c907325c69271ddf0c944bc72`

##### SHA-1
<=== SHA-1 ===>  
`9d4e1e23bd5b727046a9e3b4b7db57bd8d6ee684`

##### SHA-256
<=== SHA-256 ===>  
`d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1`

##### NTLM(NT)
<=== NTLM(NT) ===>  
`36aa83bdcab3c9fdaf321ca42a31c3fc`

<hr>
### Security Note
This script is for educational purposes only and should not be used to store or manage passwords in a production environment. Password hashing should always be done using a secure and salted hashing algorithm, such as bcrypt or Argon2.

### License
This script is licensed under the MIT License. See the `LICENSE` file for details.

### Author
Mustafa Banikhalaf

### Contributing
Contributions are welcome! If you'd like to contribute to this project, please fork the repository and submit a pull request.

### Issues
If you encounter any issues or have questions, please open an issue in this repository.

### Acknowledgments
This script uses the following libraries:

* `hashlib` for generating MD5, SHA-1, and SHA-256 hashes
* `Cryptodome` for generating NTLM hashes
* `getpass` for secure password input

Thanks for using Mustafa's Password Hasher!
