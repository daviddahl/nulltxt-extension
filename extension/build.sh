#! /bin/bash

mv built/nulltxt.xpi /tmp
cd nulltxt/
zip -r nulltxt.xpi * 
mv nulltxt.xpi ../built

echo "the nulltxt .xpi was built"
