run:
	.env/bin/python setup.py install
	.env/bin/python -m ironic_discoverd

env:
	rm -rf .env
	virtualenv .env
	.env/bin/pip install -r requirements.txt
	@echo "Run source .env/bin/activate"
