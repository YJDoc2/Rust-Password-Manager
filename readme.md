# Rust Password Manager

## description

This is just a simple password manager command line application written in Rust.
This is not particularly good or efficient, in fact it uses a json file in invoking directory to save the encrypted passwords.
This was done to move from "excited about Rust" to "actually coding in Rust" ;) :)
This uses magic-crypt crated to encrypt and decrypt the passwrods,
serde to for serialize-deserialize the maps,
passwords to score the saving passwrods and to generate random password.

## Usage

compile to file named passman.
first run passman init in the file you want to store the json file containing the passwords

Then run passman to enter interactive commandline
Supported operations are:

<ol>
<li>add account-name : to generate and save a random password</li>
<li>add account-name password : save given password</li>
<li>get all : get all account passwords</li>
<li>get account-name : get password for given account name</li>
<li>quit : to exit the program</li>
</ol>
