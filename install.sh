set -e
cd "$(dirname "$0")"
npm --prefix probejs/_parser install
python3 -m venv venv
. venv/bin/activate
uv pip install -e . || pip install -e .
