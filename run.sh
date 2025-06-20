#!/bin/sh

mkdir -p ./sample.d/.secret

export ENV_SECRET_KEY_LOCATION=./sample.d/.secret/top.secret.dat

export ENV_PLAIN_MSG_FILENAME=./sample.d/msg.plain.txt
export ENV_MSG_SIZE_MAX=1024

test -f "${ENV_SECRET_KEY_LOCATION}" || \
	dd \
		if=/dev/urandom \
		of="${ENV_SECRET_KEY_LOCATION}" \
		bs=32 \
		count=1 \
		status=progress \
		conv=fsync

echo 'helo,wrld' > ./sample.d/msg.plain.txt

export ENV_SEALED_MSG_FILENAME=./sample.d/msg.sealed.dat

echo sealing message...
ENV_SEAL=true ./rs-seal-msg |
	dd \
		if=/dev/stdin \
		of="${ENV_SEALED_MSG_FILENAME}" \
		bs=1048576 \
		status=none

echo
echo comparing the size of messages...
ls -l \
	"${ENV_PLAIN_MSG_FILENAME}" \
	"${ENV_SEALED_MSG_FILENAME}"

echo
echo comparing contents...
xxd "${ENV_PLAIN_MSG_FILENAME}"
xxd "${ENV_SEALED_MSG_FILENAME}"

export ENV_SEALED_MSG_SIZE_MAX=1024

echo
echo openeing the sealed box...
ENV_SEAL=false ./rs-seal-msg
