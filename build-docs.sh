#!/bin/bash

usage_string="usage: ./$(basename "$0") [OPTIONS]

Script for building docs from source code

Options:
  -o, --open BROWSER  Open docs after build with the provided browser
  -h, --help          Display help message and exit

Examples:
"

usage() { echo -n "$usage_string" 1>&2; }

# TODO: Derive the following default values from package meta
PROJECT="pymerkle"
SOURCE_CODE="pymerkle"
VERSION="5.0.3"
AUTHOR="fmerg"

LANG="en"
BROWSER=

while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        -o|--open)
            BROWSER="$2"
            shift
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[-] Invalid argument: $arg"
            usage
            exit 1
            ;;
    esac
done

set -e

CONTENT="docs"    # Content that is not auto-generated from docs
TARGET="docs/target"  # Will contain auto-generated files (unstaged)
CONFIG="$TARGET/source/conf.py"   # Sphinx configuration file
DEFAULT_THEME="alabaster"         # Default sphinx theme
RTD_THEME="sphinx_rtd_theme"      # Read-the-docs theme
PYTHON_THEME="python_docs_theme"  # Python docs theme
CUSTOM_THEME="$RTD_THEME"
# CUSTOM_THEME="$PYTHON_THEME"

# Generate sphinx source
rm -rf "$TARGET"
sphinx-quickstart "$TARGET" \
    --project "$PROJECT" \
    --release "$VERSION" \
    --author "$AUTHOR" \
    --language "$LANG" \
    --ext-autodoc \
    --ext-intersphinx \
    --ext-coverage \
    --ext-viewcode \
    --sep

# Adjust sphinx configuration
sed -ie "/html_theme/s/$DEFAULT_THEME/$CUSTOM_THEME/" $CONFIG
echo >> $CONFIG
echo "master_doc = 'index'" >> $CONFIG
echo "pygments_style = 'sphinx'" >> $CONFIG

# Make sphinx configuration see the source code
line_1="import os"
line_2="import sys"
line_3="sys.path.insert(0, os.path.abspath('.'))"
sed -ie "/$line_1/s/^# //" $CONFIG
sed -ie "/$line_2/s/^# //" $CONFIG
sed -ie "/$line_3/s/^# //" $CONFIG
sed -ie "/$line_3/s/('.')/('..\/..\/..')/" $CONFIG

# echo "autodoc_default_options = {'private-members': True}" >> $CONFIG
echo "extensions += ['sphinx.ext.autosectionlabel']" >> $CONFIG

if [ $CUSTOM_THEME == $PYTHON_THEME ]; then
  echo "html_sidebars = {
    '**': ['globaltoc.html', 'sourcelink.html', 'searchbox.html'],
    'using/windows': ['windowssidebar.html', 'searchbox.html']
  }" >> $CONFIG
fi

# Content auto-generated from source code
sphinx-apidoc \
    --force \
    --module-first \
    -o "$TARGET/source" $SOURCE_CODE

# Transfer non auto-generated content to sphinx source
for f in "$CONTENT"/*.rst; do
  cp "$f" "$TARGET/source/$(basename "$f")"
done

# Build html artifacts from sphinx source
sphinx-build -b html "$TARGET/source/" "$TARGET/build/html"

# Navigate locally with browser
if [ -n "$BROWSER" ]; then
    $BROWSER "$TARGET/build/html/index.html"
fi
