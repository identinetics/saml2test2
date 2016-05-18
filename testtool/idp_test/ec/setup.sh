#!/usr/bin/env bash

build_sp_conf.py -b base_conf -i sp_conf.yaml -o conf.py
mk_multi_metadata.py conf > ec_sps.xml
