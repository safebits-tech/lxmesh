#!/bin/sh

set -e

find . -path ./build -prune -o -path ./.pybuild -prune -o -path ./debian -prune -o -path ./.git -prune -o -type f \( -name '*.py' -o -executable -exec sh -c 'file {} | grep -i python >/dev/null 2>&1' \; \) -exec flake8 {} +

mypy --namespace-packages --explicit-package-bases --strict lxmesh/

find . -path ./build -prune -o -path ./.pybuild -prune -o -path ./debian -prune -o -path ./.git -prune -o -type f -executable -exec sh -c 'file {} | grep -i python >/dev/null 2>&1' \; -exec mypy --namespace-packages --explicit-package-bases --strict {} \;
