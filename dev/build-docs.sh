#!/bin/bash

usage_string="usage: ./dev/$(basename "$0") --author= [--version=] [--theme=]

 Options:
  -a, --author		package author
  -v, --version         package version [optional], defaults to 
  			the one within the __init__ file
  --theme               html theme [optional], defaults to rtd
  -h, --help            Display this help message and exit
"

usage() { echo -n "$usage_string" 1>&2; }

if [[ $1 = "-h" ]]; then
	usage
	exit 0
fi

rm -rf docs
mkdir -p docs
cd docs

AUTHOR="FoteinosMerg"
VERSION="5.0.0b3"
THEME="sphinx_rtd_theme"

for arg in $@
do
	case $arg in
		-a=*|--author=*)
			AUTHOR="${arg#*=}"
			shift
			;;
		-v=*|--version=*)
			VERSION="${arg#*=}"
			;;
		--theme=*)
			THEME="${arg#*=}"
			shift
			;;
		--default)
			DEFAULT=YES
			shift
			;;
		*)
			# unknown option
			;;
	esac
done

sphinx-quickstart -q --sep -p pymerkle -a $AUTHOR -v $VERSION\
	--ext-autodoc --ext-intersphinx \
	--ext-coverage --ext-viewcode \

sphinx-apidoc --force --module-first -o source ../pymerkle

config_file="source/conf.py"
old_theme="alabaster"
new_theme=$THEME
line_1="import os"
line_2="import sys"
line_3="sys.path.insert(0, os.path.abspath('.'))"
line_4="extensions = ["
line_5="html_theme ="

sed -ie "/$line_1/s/^# //" $config_file
sed -ie "/$line_2/s/^# //" $config_file
sed -ie "/$line_3/s/^# //" $config_file
sed -ie "/$line_3/s/('.')/('..\/..')/" $config_file
sed -ie "/$line_5/s/$old_theme/$new_theme/" $config_file

echo >> $config_file
echo "master_doc = 'index'" >> $config_file
echo "pygments_style = 'sphinx'" >> $config_file

cp ../dev/index.rst ./source/index.rst

sphinx-build -b html source build

exit 0
