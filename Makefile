run:
	flask --app main run --host=0.0.0.0 --port=5000

dev:
	FLASK_ENV=development FLASK_DEBUG=1 flask --app main run --host=0.0.0.0 --port=5000 --reload

freeze:
	pip freeze > requirements.txt