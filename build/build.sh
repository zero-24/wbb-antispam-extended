#!/bin/bash
cd ..
tar -cf files.tar lib/
tar -cf build/antispam-extended.tar xml/ files.tar package.xml languages/
rm files.tar
echo 'package ready'
