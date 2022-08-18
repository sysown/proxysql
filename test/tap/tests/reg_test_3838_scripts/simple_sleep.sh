#!/bin/sh

if [ ! "$1" ]; then
    echo { \"err\": \"Missing required operand\" }
	exit 1
fi

sleep $1

echo { \"param\": $1 }
