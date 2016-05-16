#!/usr/bin/env bash

./build_conf.py
../mk_metadata.py conf > ec_sps.xml
