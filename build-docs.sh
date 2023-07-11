#!/bin/bash

usage_string="usage: ./$(basename "$0") [OPTIONS]

Script for building docs from source code

Options:
  --theme THEME       Specify theme: alabaster, rtd or python (default: rtd)
  --open BROWSER      Open docs after build with the provided browser
  -h, --help          Display help message and exit

Examples:
"

usage() { echo -n "$usage_string" 1>&2; }

parse_project_version() {
  source_code=$1
  init_file="./${source_code}/__init__.py"
  parsed=$(sed -n 's/^__version__ = \(.*\)/\1/p' < ${init_file})
  version=$(echo $parsed | tr -d "\'")
  echo $version
}


CONTENT="docs"    # Content that is not auto-generated from docs
TARGET="docs/target"  # Will contain auto-generated files (unstaged)
CONFIG="$TARGET/source/conf.py"   # Sphinx configuration file
ALABASTER_THEME="alabaster"       # Default sphinx theme
RTD_THEME="sphinx_rtd_theme"      # Read-the-docs theme
PYTHON_THEME="python_docs_theme"  # Python docs theme

LANG="en"
BROWSER=

PROJECT="pymerkle"
SOURCE_CODE="pymerkle"
VERSION=$(parse_project_version "$SOURCE_CODE")
AUTHOR="fmerg"


THEME="$RTD_THEME"

while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        --open)
            BROWSER="$2"
            shift
            shift
            ;;
        --theme)
            case $2 in
                alabaster)
                    THEME="$ALABASTER_THEME"
                    ;;
                rtd)
                    THEME="$RTD_THEME"
                    ;;
                python)
                    THEME="$PYTHON_THEME"
                    ;;
                *)
                    echo "[-] Unsupported theme: $arg"
                    usage
                    exit 1
                    ;;
            esac
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
sed -ie "/html_theme/s/$ALABASTER_THEME/$THEME/" $CONFIG
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
echo "extensions += ['sphinx_toolbox.collapse']" >> $CONFIG

if [ $THEME == $PYTHON_THEME ]; then
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
