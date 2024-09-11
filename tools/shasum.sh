#!/bin/sh

shasum $1 | cut -f 1 -d ' '
