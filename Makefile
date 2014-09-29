run:
	.env/bin/python discoverd.py

env:
	rm -rf .env
	virtualenv .env
	.env/bin/pip install -r requirements.txt
	@echo "Run source .env/bin/activate"
