#!/bin/bash
cd ..
tar -cf files.tar lib/
tar -cf build/antispam-extended.tar xml/ files.tar package.xml
rm files.tar
echo 'package ready'