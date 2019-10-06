#!/bin/bash

rm -rf docs
mkdir -p docs
cd docs

#pip install sphinx_rtd_theme

sphinx-quickstart -q --sep -p pymerkle -a FoteinosMerg -v 5.0.0b3\
	--ext-autodoc --ext-intersphinx \
	--ext-coverage --ext-viewcode \

sphinx-apidoc --force --module-first -o source ../pymerkle

filename="source/conf.py"
old_theme="alabaster"
new_theme="sphinx_rtd_theme"
line_1="import os"
line_2="import sys"
line_3="sys.path.insert(0, os.path.abspath('.'))"
line_4="extensions = ["
line_5="html_theme ="

sed -i -e "/$line_1/s/^# //" $filename
sed -i -e "/$line_2/s/^# //" $filename
sed -i -e "/$line_3/s/^# //" $filename
sed -i -e "/$line_3/s/('.')/('..\/..')/" $filename
sed -i -e "/$line_5/s/$old_theme/$new_theme/" $filename
echo >> $filename
echo "master_doc = 'index'" >> $filename

cp ../dev/index.rst ./source/index.rst

sphinx-build -b html source build

exit 0
