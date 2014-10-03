run:
	.env/bin/python setup.py install
	.env/bin/python -m ironic_discoverd

test:
	.env/bin/flake8 ironic_discoverd
	.env/bin/python -m unittest ironic_discoverd.test

env:
	rm -rf .env
	virtualenv .env
	.env/bin/pip install -r requirements.txt
	@echo "Run source .env/bin/activate"

test_env: env
	.env/bin/pip install flake8 mock
