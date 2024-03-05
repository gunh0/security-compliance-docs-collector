from flask import Flask, render_template
import os
import json

app = Flask(__name__)


def get_docs_structure(root_dir="docs"):
    structure = {}
    for root, dirs, files in os.walk(root_dir):
        path = root.split(os.sep)
        current = structure
        for d in path[1:]:
            if d not in current:
                current[d] = {}
            current = current[d]
        for file in files:
            if file.endswith(".json"):
                current[file] = os.path.join(root, file)
    return structure


def read_json_file(file_path):
    with open(file_path, "r") as file:
        return json.load(file)


@app.route("/")
def index():
    docs_structure = get_docs_structure()
    return render_template("index.html", structure=docs_structure)


@app.route("/view/<path:file_path>")
def view_file(file_path):
    full_path = os.path.join("docs", file_path)
    if os.path.exists(full_path) and full_path.endswith(".json"):
        content = read_json_file(full_path)
        return render_template("view_file.html", file_path=file_path, content=content)
    else:
        return "File not found", 404


if __name__ == "__main__":
    app.run(debug=True)
