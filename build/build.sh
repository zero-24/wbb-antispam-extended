#!/bin/bash
cd ..
tar -cf files.tar lib/
tar -cf build/antispam-extended.tar files.tar package.xml languages/ eventListener.xml option.xml userGroupOption.xml
rm files.tar
echo 'package ready'
