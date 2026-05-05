#!/usr/bin/bash
find /proc -maxdepth 4 -lname \*$1\* 2>/dev/null 
