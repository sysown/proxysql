#!/bin/bash

TAP_HOST="${TAP_HOST:=127.0.0.1}"
TAP_PORT="${TAP_PORT:=3306}"
TAP_USERNAME="${TAP_USERNAME:=root}"
TAP_PASSWORD="${TAP_PASSWORD:=a}"

export TAP_HOST
export TAP_PORT
export TAP_USERNAME
export TAP_PASSWORD

ret=`prove --ext -t ./tests/`
echo "$ret"

if [[ $ret == *"FAIL"* ]]; then
	exit 1
fi

ret=`prove --ext .my --source MyTAP --mytap-option database=tap --mytap-option user=root --mytap-option password=a --mytap-option suffix=.my`
echo "$ret"

if [[ $ret == *"FAIL"* ]]; then
	exit 1
fi


