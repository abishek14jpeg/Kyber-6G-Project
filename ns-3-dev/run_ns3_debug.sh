#!/bin/bash
cd "/home/abishek14/Kyber-6G project/ns-3-dev"
export PYTHONPATH=./bindings/python:$PYTHONPATH
python3 ./ns3 --version > /tmp/ns3_out.txt 2>&1
cat /tmp/ns3_out.txt
