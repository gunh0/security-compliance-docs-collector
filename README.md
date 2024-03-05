# Security Compliance Docs Collector

This tool collects and displays security compliance documents from various cloud providers.
It provides an easy-to-use interface for viewing the contents of these documents.

### Environment

- Python 3.11.9

### Installation

1. Clone the repository:

```sh
clone https://github.com/your-username/security-compliance-docs-collector.git
cd security-compliance-docs-collector
```

2. Create a virtual environment and activate it:

```sh
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install the required packages:

```sh
pip install -r requirements.txt
```

### Usage

1. Start the Flask development server:

```sh
make run
```

2. Open a web browser and navigate to <http://localhost:5000>.

3. Browse the list of available compliance documents and click on any document to view its contents.

### Features

- Display a list of security compliance documents organized by cloud provider
- View the contents of JSON-formatted compliance documents in an interactive tree structure
- Easy navigation between document list and individual document views

### License

This project is licensed under the Apache License 2.0
