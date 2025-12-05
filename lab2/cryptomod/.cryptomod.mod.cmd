savedcmd_/home/timchen/lab2/cryptomod/cryptomod.mod := printf '%s\n'   cryptomod.o | awk '!x[$$0]++ { print("/home/timchen/lab2/cryptomod/"$$0) }' > /home/timchen/lab2/cryptomod/cryptomod.mod
