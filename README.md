# AsyncIO Client Server App

## Description

A simple client server app that swaps the cases of a message. Message is encoded before being sent and subsequently decoded by the server/client 

## Installation

[Optional] create a virtual environment then activate
```sh
virtualenv mtcs
source mtcs/bin/activate
```

Install the required packages by running:

```sh
pip install -r requirements.txt
```

## Usage

### Server

Start the server by running:

```sh
python server.py
```

### Client

Connect to the server by running:

```sh
python client.py
```

## Running Tests

Run the tests by using pytest:

```sh
pytest
```

* for the test, we need to run the server first for it to work. had no time to debug why the server is not running from the test file.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details