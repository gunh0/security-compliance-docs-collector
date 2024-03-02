run:
	flask --app main run --host=0.0.0.0 --port=5000

freeze:
	pip freeze > requirements.txt