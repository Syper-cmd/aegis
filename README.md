# Aegis

## What is it?
This program is a CLI utility for encrypting and hiding information within Windows PE files.

## How to use?
This program has three main "branches" of commands:

`aegis keygen` - The command is used to generate an encryption key. For more information, see the built-in help.

`aegis encode` - The command is used to encrypt text and hide it within a PE file. For more information, see the built-in help.

`aegis decode` - The command is used to extract encrypted text and decrypt it using a key. For more information, see the built-in help.

## How to build?
This program is quite easy to assemble. It uses only two commands:
- `go mod download`
- `go build`

## Tests
If you need to check the security or quality of PE files, there is a set of scripts in the `scripts` folder. You can run them using the simple command `go run name_of_script.go`.
