#!/bin/bash
./config
make -j 8
sudo make -j 8 install
